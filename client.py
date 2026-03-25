import socket

# We'll make this cleaner later
SERVERS = ["127.0.0.2"] # We'll try to have multiple
PORT = 8000 # We can re-use this if we have different hosts 

for server in SERVERS:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP
        # s.settimeout(5)
        s.connect((server, PORT))
        print(f"Connected to server {server}:{PORT}")

        while True:
            message = input("Enter a message to send (or 'exit' to quit): ")
            if message.lower() == 'exit':
                print("Exiting client.")
                break
            s.sendall(message.encode())
            data = s.recv(1024)
            print(f"Received from server: {data.decode()}")
    except Exception as e:
        print(f"[Client]: Failed to connect to server {server}:{PORT} - {e}")