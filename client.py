import socket
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# hard-coded relays for now
ENTRY = "127.0.0.2"
MIDDLE = "127.0.0.3"
EXIT = "127.0.0.4" 
PORT = 8000 # We can re-use this if we have different hosts 

# for encryption layers
KEYS = ["b9d3caba51860cafb725bfc0fcf3417f32975bfb4cb3079da443d8654048f5ae", "7b556e69ea5185904294f0fa86b81e822c2d9a4e688959afc5ec12bd5cb7fa39", "3a41a49e99b6921874c23104d4957e153319521ff9211a41721df79929dff54d"]

def main():
	
	ciphers = cipher_gen()
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP
		s.connect((ENTRY, PORT))
		print(f"Connected to server {ENTRY}:{PORT}")
		while True:
			message = input("Enter a message to send (or 'exit' to quit): ")
			if message.lower() == 'exit':
				print("Exiting client.")
				break

			# wrap the message in 'onion' layers
			# for now, I'm just creating the protocol as "next_IP|message"
			# we can change this because otherwise the payload itself might contain a "|"
			data = construct_message(message, ciphers)

			s.sendall(data)
			recv_data = s.recv(4096)
			print(f"Received from server: {recv_data.decode()}")
	except Exception as e:
		print(f"[Client]: Failed to connect to server {ENTRY}:{PORT} - {e}")

def cipher_gen():
	aesgcm1 = AESGCM(bytes.fromhex(KEYS[0]))
	aesgcm2 = AESGCM(bytes.fromhex(KEYS[1]))
	aesgcm3 = AESGCM(bytes.fromhex(KEYS[2]))
	
	return aesgcm1, aesgcm2, aesgcm3
	
def construct_message(msg, ciphers):
 	# pass nonce with the message so we can decrypt
	# exit layer
	nonce3 = os.urandom(12)
	layer3 = nonce3 + ciphers[2].encrypt(nonce3, f"FINAL|{msg}".encode(), None)
	
	# middle layer
	nonce2 = os.urandom(12)
	layer2 = nonce2 + ciphers[1].encrypt(nonce2, f"{EXIT}|".encode() + layer3, None)
	
	# middle layer
	nonce1 = os.urandom(12)
	layer1 = nonce1 + ciphers[0].encrypt(nonce1, f"{MIDDLE}|".encode() + layer2, None)
	
	return layer1
	
if __name__ == "__main__":
	main()
