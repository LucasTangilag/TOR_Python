import socket
import sys
import os
import signal

PORT = 8000


def run_server(host):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, PORT))
    s.listen()
    print(f"[PID {os.getpid()}] Server listening on {host}:{PORT}", flush=True)

    while True:
        conn, addr = s.accept()
        print(f"[PID {os.getpid()}] Connection from {addr} -> {host}:{PORT}!", flush=True)
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(f"[PID {os.getpid()}] Received from {addr}: {data.decode()}", flush=True)
            conn.sendall(data)
        conn.close()


def parse_ips():
    args = sys.argv[1:]
    if not args:
        print("Usage: server.py <ip1> <ip2> ...  OR  server.py --file <ips.txt>")
        sys.exit(1)

    if args[0] == "--file":
        if len(args) < 2:
            print("Error: --file requires a path argument")
            sys.exit(1)
        with open(args[1]) as f:
            return [line.strip() for line in f if line.strip()]

    return args


def main():
    ips = parse_ips()
    pids = []

    def shutdown(sig, frame):
        print("\nShutting down all servers...")
        for pid in pids:
            os.kill(pid, signal.SIGTERM)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    for ip in ips:
        pid = os.fork()
        if pid == 0:
            run_server(ip)
            sys.exit(0)
        else:
            print(f"Forked server for {ip} (PID {pid})")
            pids.append(pid)

    for pid in pids:
        os.waitpid(pid, 0)


if __name__ == "__main__":
    main()