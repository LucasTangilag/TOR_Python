import socket
import sys
import os
import signal

PORT = 8000 # fixed for now

# start relay
def run_relay(host):
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
            print(f"[PID {os.getpid()}] Received from {addr}: {data.decode()}", flush=True)
            
            # 'peel' onion layer from received data
            # assumes protocol is "next_IP|message" 
            raw_msg = data.decode()
            if "|" not in raw_msg:
                print(f"[PID {os.getpid()}] Malformed message from {addr}: {raw_msg}", flush=True)
                break
            
            # if this is not the exit node, the raw message should be "current_IP|next_IP|message"
            # otherwise, if this *IS* the exit, it's "FINAL|message"
            try:
                current_hop, next_hop, msg = raw_msg.split("|", 2)
            except Exception as e:
                next_hop, msg = raw_msg.split("|", 1)
                if next_hop != "FINAL":
                    print(f"[PID {os.getpid()}] Malformed message from {addr}: {raw_msg}", flush=True)
                    break

            # if this is the exit node, start responding back to client
            if next_hop == "FINAL":
                print(f"[PID {os.getpid()}] Final destination reached with message: {msg}", flush=True)
                
                # for now, let's just echo the message back to the client 
                response = f"You've successfully reached {host} with message: {msg}"
                conn.sendall(response.encode())
                break
            
            # otherwise, forward to next hop
            next_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            next_conn.connect((next_hop, PORT))
            print(f"[PID {os.getpid()}] Forwarding to {next_hop}:{PORT} -> {f"{next_hop}|{msg}"}", flush=True)
            next_conn.sendall(msg.encode())

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

def main():
    ips = parse_ips()
    pids = [] #process ids for forked server insances 

    #closing
    def shutdown(sig, frame):
        print("\nShutting down all servers...")
        for pid in pids:
            os.kill(pid, signal.SIGTERM)
        sys.exit(0)
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    #fork servers for each IP
    for ip in ips:
        pid = os.fork()
        if pid == 0:
            run_relay(ip)
            sys.exit(0)
        else:
            print(f"Forked server for {ip} (PID {pid})")
            pids.append(pid)

    for pid in pids:
        os.waitpid(pid, 0)


if __name__ == "__main__":
    main()