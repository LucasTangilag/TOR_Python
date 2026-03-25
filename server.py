import socket
import sys

HOST = sys.argv[1] # Server IP e.g. 127.0.0.2 or whatever
PORT = 8000 

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP
s.bind((HOST, PORT))
s.listen()
print(f"Server listening on {HOST}:{PORT}")

while True:
    conn, addr = s.accept() 
    print(f"Connecttion from {addr} -> {HOST}:{PORT}!")
    while True:
        data = conn.recv(1024)
        if not data:
            break
        print(f"Received from {addr}: {data.decode()}")
        conn.sendall(data)
    conn.close()