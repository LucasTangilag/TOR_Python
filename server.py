import socket
import sys
import os
import signal
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PORT = 8000 # fixed for now

# for decrypting different layers
KEYS = ["b9d3caba51860cafb725bfc0fcf3417f32975bfb4cb3079da443d8654048f5ae", "7b556e69ea5185904294f0fa86b81e822c2d9a4e688959afc5ec12bd5cb7fa39", "3a41a49e99b6921874c23104d4957e153319521ff9211a41721df79929dff54d"]

# start relay
def run_relay(host, cipher):
	# set up lister for host
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind((host, PORT))
	s.listen()
	print(f"[PID {os.getpid()}] Relay listening on {host}:{PORT}", flush=True)

	while True:

		# relay has knowledge of previous sender here
		conn, addr = s.accept()
		print(f"[PID {os.getpid()}] Connection from {addr} -> {host}:{PORT}!", flush=True)
        
		while True:

			# receive from previous relay
			data = conn.recv(4096)
			if not data:
				break
			print(f"[PID {os.getpid()}] Received from {addr}: {data}", flush=True)
            
			# 'peel' onion layer from received data
			# assumes protocol is "next_IP|message" 
			raw_msg = data
            
			# extract nonce for decryption
			nonce = raw_msg[:12]
			ciphertext = raw_msg[12:]
            
			# decrypt
			plaintext = cipher.decrypt(nonce, ciphertext, None)
			print(f"[PID {os.getpid()}] Decrypted Message {plaintext}", flush=True)
            
			if b"|" not in plaintext:
				print(f"[PID {os.getpid()}] Malformed message from {addr}: {raw_msg}", flush=True)
				break
            
			# split into next hop and remaining payload
			split_idx = plaintext.index(b"|")
			next_hop = plaintext[:split_idx].decode()
			msg = plaintext[split_idx + 1:]  
           
			# if this is the exit node, start responding back to client
			if next_hop == "FINAL":
				print(f"[PID {os.getpid()}] Final destination reached with message: {msg}", flush=True)
                
				# for now, let's just echo the message back to the client 
				response = f"You've successfully reached {host} with message: {msg}"
				conn.sendall(response.encode())
				break
            
			# otherwise, forward to next hop
			next_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			next_conn.bind((host, 0))
			next_conn.connect((next_hop, PORT))
			print(f"[PID {os.getpid()}] Forwarding to {next_hop}:{PORT} -> {f"{msg}"}", flush=True)
			next_conn.sendall(msg)

			# send response back to previous relay
			response = next_conn.recv(4096)
			conn.sendall(response)

            
		conn.close()


def parse_ips():
	args = sys.argv[1:]
	if not args: # no args provided 
		print("Usage: server.py <ip1> <ip2> ...  OR  server.py --file <ips.txt>")
		sys.exit(1)

	if args[0] == "--file":
		if len(args) < 2: # no file
			print("Error: --file requires a path argument")
			sys.exit(1)
		with open(args[1]) as f:
			return [line.strip() for line in f if line.strip()]

	return args
    
def cipher_gen():
	aesgcm1 = AESGCM(bytes.fromhex(KEYS[0]))
	aesgcm2 = AESGCM(bytes.fromhex(KEYS[1]))
	aesgcm3 = AESGCM(bytes.fromhex(KEYS[2]))

	return aesgcm1, aesgcm2, aesgcm3

def main():
	ips = parse_ips()
	pids = [] #process ids for forked server insances 

	# get decryption ciphers
	ciphers = cipher_gen()
	
	#closing
	def shutdown(sig, frame):
		print("\nShutting down all servers...")
		for pid in pids:
			os.kill(pid, signal.SIGTERM)
		sys.exit(0)
	signal.signal(signal.SIGINT, shutdown)
	signal.signal(signal.SIGTERM, shutdown)

	#fork servers for each IP
	i = 0
	for ip in ips:
		pid = os.fork()
		if pid == 0:
			run_relay(ip, ciphers[i])
			sys.exit(0)
		else:
			print(f"Forked server for {ip} (PID {pid})")
			pids.append(pid)
		i = i + 1

	for pid in pids:
		os.waitpid(pid, 0)


if __name__ == "__main__":
	main()
