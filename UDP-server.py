#!/usr/bin/env python3
import socket
import sys
import signal
from datetime import datetime

server_socket = None
shutdown_requested = False


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    global shutdown_requested
    print("\n[SERVER] Interrupt received — shutting down...")
    shutdown_requested = True


def main():
    global server_socket

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <port>")
        sys.exit(1)

    port = int(sys.argv[1])
    host = "0.0.0.0"

    signal.signal(signal.SIGINT, signal_handler)
    try:
        signal.signal(signal.SIGTERM, signal_handler)
    except AttributeError:
        pass

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))
    server_socket.settimeout(1.0) 
    print(f"[SERVER] UDP server listening on port {port} (Ctrl+C to stop)...\n")

    try:
        while not shutdown_requested:
            try:
                data, client_addr = server_socket.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:
                break

            print(f"[SERVER] Received request from {client_addr}")

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            print(f"[SERVER] Sending timestamp: {timestamp}")

            server_socket.sendto(timestamp.encode("utf-8"), client_addr)

    except Exception as e:
        print(f"[SERVER] Error: {e}")

    finally:
        if server_socket:
            server_socket.close()
        print("[SERVER] Shutdown complete.")


if __name__ == "__main__":
    main()
