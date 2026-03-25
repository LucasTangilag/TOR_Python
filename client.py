import socket

# We'll make this cleaner later
SERVERS = ["127.0.0.2", "127.0.0.3", "127.0.0.4"] # hard-coded relays for now
PORT = 8000 # We can re-use this if we have different hosts 

def main():
    for server in SERVERS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP
            s.connect((server, PORT))
            print(f"Connected to server {server}:{PORT}")

            while True:
                message = input("Enter a message to send (or 'exit' to quit): ")
                if message.lower() == 'exit':
                    print("Exiting client.")
                    break

                # wrap the message in 'onion' layers
                # for now, I'm just creating the protocol as "next_IP|message"
                # we can change this because otherwise the payload itself might contain a "|"
                for relay in reversed(SERVERS):
                    if relay == SERVERS[-1]: 
                        # last relay, so message is the final destination
                        # for now, I'll mark it as "FINAL|message"
                        message = f"FINAL|{message}"
                    else:    
                        message = f"{relay}|{message}"

                s.sendall(message.encode())
                data = s.recv(4096)
                print(f"Received from server: {data.decode()}")
        except Exception as e:
            print(f"[Client]: Failed to connect to server {server}:{PORT} - {e}")

if __name__ == "__main__":
    main()