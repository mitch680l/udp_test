#!/usr/bin/env python3
import socket
import sys
from datetime import datetime

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <server_ip> <port>")
        sys.exit(1)

    server_ip = sys.argv[1]
    port = int(sys.argv[2])

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:

        send_time = datetime.now()
        send_str = send_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        client_socket.connect((server_ip, port))
        print(f"[CLIENT] Connected at:         {send_str}")

        data = client_socket.recv(1024).decode("utf-8")


        recv_time = datetime.now()
        recv_str = recv_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        print(f"[CLIENT] Received server time: {data}")
        print(f"[CLIENT] Received at:          {recv_str}")

        server_dt = datetime.strptime(data, "%Y-%m-%d %H:%M:%S.%f")
        send_dt = datetime.strptime(send_str, "%Y-%m-%d %H:%M:%S.%f")
        recv_dt = datetime.strptime(recv_str, "%Y-%m-%d %H:%M:%S.%f")

        clock_diff_ms = abs((recv_dt - server_dt).total_seconds() * 1000)
        rtt_ms = (recv_dt - send_dt).total_seconds() * 1000

        print(f"[CLIENT] Clock difference: {clock_diff_ms:.3f} ms")
        print(f"[CLIENT] Round-trip time:  {rtt_ms:.3f} ms")


if __name__ == "__main__":
    main()
