import socket
import sys
import os
import signal
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PORT = 8000

# encryption toggle (for testing)
# make sure that client.py and server.py have the same value for this variable
USE_ENCRYPTION = True

# keys must match client.py KEYS list, in the same order
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

def cipher_gen():
    return [AESGCM(bytes.fromhex(k)) for k in KEYS]

def encrypt_layer(cipher, message):
    """Prepend a random nonce to the AES-GCM ciphertext."""
    if not USE_ENCRYPTION:
        return message if isinstance(message, bytes) else message.encode()
    if isinstance(message, str):
        message = message.encode()
    nonce = os.urandom(12)
    return nonce + cipher.encrypt(nonce, message, None)

def decrypt_layer(cipher, raw):
    """Split nonce from ciphertext and decrypt. Returns None on failure."""
    if not USE_ENCRYPTION:
        return raw
    nonce      = raw[:12]
    ciphertext = raw[12:]
    try:
        return cipher.decrypt(nonce, ciphertext, None)
    except Exception as e:
        print(f"[PID {os.getpid()}] Decryption failed: {e}", flush=True)
        return None

def run_relay(host, cipher):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORT))
    s.listen()
    print(f"[PID {os.getpid()}] Relay listening on {host}:{PORT}", flush=True)

    while True:

        # relay has knowledge of previous sender here
        prev_conn, addr = s.accept()
        print(f"[PID {os.getpid()}] Connection from {addr}", flush=True)

        try: 
            _handle(prev_conn, addr, host, cipher) # receive from previous relay (refactored from previous logic within run_relay)
        except Exception as e:
            print(f"[PID {os.getpid()}] Unhandled error: {e}", flush=True)
        finally:
            prev_conn.close()


def _handle(prev_conn, addr, host, cipher):
    while True:
        data = recv_msg(prev_conn)
        if not data:
            print(f"[PID {os.getpid()}] Connection closed by {addr}", flush=True)
            break

        print(f"[PID {os.getpid()}] Received from {addr}: {data}", flush=True)

        # 'peel' onion layer from received data
        plaintext = decrypt_layer(cipher, data)
        if plaintext is None:
            break   # uh-oh

		# assumes protocol is "next_IP|message" 
		# split into next hop and remaining payload
        if b"|" not in plaintext:
            print(f"[PID {os.getpid()}] Malformed message (no '|')", flush=True)
            break

        split_idx = plaintext.index(b"|")
        next_hop  = plaintext[:split_idx].decode()
        msg       = plaintext[split_idx + 1:]

        print(f"[PID {os.getpid()}] Next hop: {next_hop}", flush=True)

        # IF THIS NODE IS THE EXIT NODE
        if next_hop == "FINAL":
            if b"|" not in msg:
                print(f"[PID {os.getpid()}] Malformed FINAL payload", flush=True)
                break

            split_dest   = msg.index(b"|")
            dest         = msg[:split_dest].decode()
            http_request = msg[split_dest + 1:]
            dest_ip, dest_port = dest.rsplit(":", 1)

            print(f"[PID {os.getpid()}] Exit node: connecting to {dest_ip}:{dest_port}", flush=True)

            # now start the HTTP request
            try:
                server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_conn.connect((dest_ip, int(dest_port)))
                server_conn.sendall(http_request)

                server_response = b""
                while True:
                    chunk = server_conn.recv(4096)
                    if not chunk:
                        break
                    server_response += chunk
                server_conn.close()

                print(f"[PID {os.getpid()}] Exit node: received {len(server_response)} bytes", flush=True)
            except Exception as e:
                print(f"[PID {os.getpid()}] Failed to reach destination: {e}", flush=True)
                break

            send_msg(prev_conn, encrypt_layer(cipher, server_response))
            break  

        # otherwise, forward to next hop
        try:
            next_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            next_conn.bind((host, 0))
            next_conn.connect((next_hop, PORT))
        except Exception as e:
            print(f"[PID {os.getpid()}] Failed to connect to {next_hop}: {e}", flush=True)
            break

        print(f"[PID {os.getpid()}] Forwarding {len(msg)} bytes to {next_hop}:{PORT}", flush=True)
        send_msg(next_conn, msg)

        # ecrypt and send response back to previous relay
        response = recv_msg(next_conn)
        next_conn.close()

        if response is None:
            print(f"[PID {os.getpid()}] No response from {next_hop}", flush=True)
            break

        send_msg(prev_conn, encrypt_layer(cipher, response))
        break 


def parse_args():
    """Usage: server.py <key_index> <host_ip>"""
    args = sys.argv[1:]
    if len(args) != 2:
        print("Usage: server.py <key_index> <host_ip>")
        print("  key_index: 0 = entry, 1 = middle, 2 = exit")
        sys.exit(1)
    try:
        key_index = int(args[0])
    except ValueError:
        print(f"key_index must be an integer, got: {args[0]}")
        sys.exit(1)
    if key_index not in range(len(KEYS)):
        print(f"key_index must be 0–{len(KEYS) - 1}, got: {key_index}")
        sys.exit(1)
    return key_index, args[1]


def main():
    key_index, host = parse_args()
    ciphers = cipher_gen()
    cipher  = ciphers[key_index]

    print(f"[PID {os.getpid()}] Starting relay — host={host}, key_index={key_index}", flush=True)

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    run_relay(host, cipher)


if __name__ == "__main__":
    main()