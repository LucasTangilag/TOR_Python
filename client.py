import socket
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from urllib.parse import urlparse

# encryption toggle (for testing)
# make sure that client.py and server.py have the same value for this variable
USE_ENCRYPTION = True

# hard-coded relays for now
ENTRY = "127.0.0.2"
MIDDLE = "127.0.0.3"
EXIT = "127.0.0.4" 
PORT = 8000 # We can re-use this if we have different hosts 

# for encryption layers
KEYS = ["b9d3caba51860cafb725bfc0fcf3417f32975bfb4cb3079da443d8654048f5ae", "7b556e69ea5185904294f0fa86b81e822c2d9a4e688959afc5ec12bd5cb7fa39", "3a41a49e99b6921874c23104d4957e153319521ff9211a41721df79929dff54d"]

# the following 3 helpers were adapted from https://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data 
# they were used to determine message boundaries (since when the HTTP response is sent back, encrypted, 
# and re-wrapped as an 'onion', it might eventually overflow the recv buffer)
def send_msg(sock, data: bytes):
    sock.sendall(len(data).to_bytes(4, 'big') + data) # 'big' is big endian

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
	length = int.from_bytes(raw_len, 'big')
	return _recvall(sock, length)

# no HTTPS
def is_URL_input_ok(url):
    try:
        result = urlparse(url)
        if result.scheme != 'http':
            return False
        if not result.hostname:
            return False
        return True
    except ValueError:
        return False

# banner
def colored_ascii():
    GREEN = "\033[92m"
    RESET = "\033[0m"

    print(f"{GREEN}" + r"""
       ______ ____   ____ 
      /_  __// __ \ / __ \
       / /  / / / // /_/ /
      / /  / /_/ // _, _/ 
     /_/   \____//_/ |_|  
    """ + f"{RESET}")

def main():
    ciphers = cipher_gen()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ENTRY, PORT))
    colored_ascii()
    print(f"Connected to entry node {ENTRY}:{PORT}")

    while True:
        url = input("Enter a URL (e.g. http://example.com) or 'exit': ")
        if url.lower() == 'exit':
            break

        if not is_URL_input_ok(url):
            print("Invalid URL. Please enter a valid HTTP URL. (HTTPS not supported)")
            continue

        data = construct_message(url, ciphers)
        send_msg(s, data)

        # refactor:
        # with the helpers from above, we don't need to repeatedly call recv on chunks now
        raw = b""
        raw = recv_msg(s)

        response = decrypt_response(raw, ciphers)
        print(f"\n--- Response ---\n{response.decode(errors='replace')}")
  

def decrypt_response(data, ciphers):
    # decrypt each layer

    if not USE_ENCRYPTION:
        return data

    onion = data
    for i in range(3):
		# extract nonce for decryption
        nonce = onion[:12]
        ciphertext = onion[12:]
        plaintext = ciphers[i].decrypt(nonce, ciphertext, None)
        onion = plaintext
    return onion
	
	
	
def cipher_gen():
	aesgcm1 = AESGCM(bytes.fromhex(KEYS[0]))
	aesgcm2 = AESGCM(bytes.fromhex(KEYS[1]))
	aesgcm3 = AESGCM(bytes.fromhex(KEYS[2]))
	
	return aesgcm1, aesgcm2, aesgcm3
	
def construct_message(url, ciphers):
    parsed = urlparse(url)
    host = parsed.hostname
    port  = parsed.port or 80
    path  = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    # HTTP request that will be recognized and dealth with at the exit node
    http_req = (
        f"GET {path} HTTP/1.0\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    if not USE_ENCRYPTION:
        payload3 = f"FINAL|{host}:{port}|".encode() + http_req
        layer2 = f"{EXIT}|".encode() + payload3
        layer1 = f"{MIDDLE}|".encode() + layer2
        return layer1

    # innermost layer with the actual destination
    payload3 = f"FINAL|{host}:{port}|".encode() + http_req
    nonce3 = os.urandom(12)
    layer3 = nonce3 + ciphers[2].encrypt(nonce3, payload3, None)

    nonce2 = os.urandom(12)
    layer2 = nonce2 + ciphers[1].encrypt(nonce2, f"{EXIT}|".encode() + layer3, None)

    nonce1 = os.urandom(12)
    layer1 = nonce1 + ciphers[0].encrypt(nonce1, f"{MIDDLE}|".encode() + layer2, None)

    return layer1
	
if __name__ == "__main__":
	main()
