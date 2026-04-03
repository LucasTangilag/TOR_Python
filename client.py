import socket
import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from urllib.parse import urlparse

# encryption toggle (for testing)
# make sure that client.py and server.py have the same value for this variable
USE_ENCRYPTION = True

# hard-coded relay hostnames (must match docker-compose service names)
ENTRY  = "entry"
MIDDLE = "middle"
EXIT   = "exit"
PORT   = 8000

# keys must match server.py KEYS list, in the same order
KEYS = [
    "b9d3caba51860cafb725bfc0fcf3417f32975bfb4cb3079da443d8654048f5ae",
    "7b556e69ea5185904294f0fa86b81e822c2d9a4e688959afc5ec12bd5cb7fa39",
    "3a41a49e99b6921874c23104d4957e153319521ff9211a41721df79929dff54d",
]

# the following 3 helpers were adapted from https://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data 
# they were used to determine message boundaries (since when the HTTP response is sent back, encrypted, 
# and re-wrapped as an 'onion', it might eventually overflow the recv buffer)
def send_msg(sock, data: bytes):
    sock.sendall(len(data).to_bytes(4, "big") + data)

def _recvall(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def recv_msg(sock):
    raw_len = _recvall(sock, 4)
    if not raw_len:
        return None
    length = int.from_bytes(raw_len, "big")
    return _recvall(sock, length)

# cipher setip

def cipher_gen():
    return [AESGCM(bytes.fromhex(k)) for k in KEYS]

# 'onion' construction 

def construct_message(url, ciphers):
    parsed   = urlparse(url)
    host     = parsed.hostname
    port     = parsed.port or 80
    path     = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    http_req = (
        f"GET {path} HTTP/1.0\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    if not USE_ENCRYPTION:
        payload3 = f"FINAL|{host}:{port}|".encode() + http_req
        layer2   = f"{EXIT}|".encode()   + payload3
        layer1   = f"{MIDDLE}|".encode() + layer2
        return layer1

    # innermost: exit node's payload
    payload3 = f"FINAL|{host}:{port}|".encode() + http_req
    nonce3   = os.urandom(12)
    layer3   = nonce3 + ciphers[2].encrypt(nonce3, payload3, None)

    # middle
    nonce2 = os.urandom(12)
    layer2 = nonce2 + ciphers[1].encrypt(nonce2, f"{EXIT}|".encode() + layer3, None)

    # outermost / entry layer
    nonce1 = os.urandom(12)
    layer1 = nonce1 + ciphers[0].encrypt(nonce1, f"{MIDDLE}|".encode() + layer2, None)

    return layer1


def decrypt_response(data, ciphers):
    if not USE_ENCRYPTION:
        return data

    onion = data
    for cipher in ciphers:          # ciphers[0] first (outermost), [2] last
        nonce      = onion[:12]
        ciphertext = onion[12:]
        onion      = cipher.decrypt(nonce, ciphertext, None)
    return onion

def is_url_ok(url):
    try:
        r = urlparse(url)
        return r.scheme == "http" and bool(r.hostname)
    except ValueError:
        return False

def print_banner():
    GREEN = "\033[92m"
    RESET = "\033[0m"
    print(GREEN + r"""
       ______ ____   ____ 
      /_  __// __ \ / __ \
       / /  / / / // /_/ /
      / /  / /_/ // _, _/ 
     /_/   \____//_/ |_|  
    """ + RESET)

def main():
    ciphers = cipher_gen()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print("Connecting to entry node...")
    while True:
        try:
            s.connect((ENTRY, PORT))
            break
        except ConnectionRefusedError:
            print("Entry node not ready, retrying in 2 seconds...")
            time.sleep(2)

    print_banner()
    print(f"Connected to entry node {ENTRY}:{PORT}\n")

    try:
        while True:
            url = input("Enter a URL (e.g. http://example.com) or 'exit': ").strip()
            if url.lower() == "exit":
                break

            if not is_url_ok(url):
                print("Invalid URL. Only plain HTTP is supported (no HTTPS).\n")
                continue

            send_msg(s, construct_message(url, ciphers))

            raw = recv_msg(s)
            if raw is None:
                print("Connection closed by relay.\n")
                break

            try:
                response = decrypt_response(raw, ciphers)
                print(f"\n--- Response ---\n{response.decode(errors='replace')}\n")
            except Exception as e:
                print(f"Failed to decrypt response: {e}\n")
    finally:
        s.close()


if __name__ == "__main__":
    main()