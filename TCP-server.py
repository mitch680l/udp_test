import socket
import sys
import signal
from datetime import datetime

server_socket = None
shutdown_requested = False


def signal_handler(sig, frame):
    """Handle Ctrl+C or termination signals."""
    global shutdown_requested
    print("\n[SERVER] Interrupt signal received — shutting down...")
    shutdown_requested = True


def main():
    global server_socket

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <port>")
        sys.exit(1)

    port = int(sys.argv[1])
    host = "0.0.0.0"

    # Register SIGINT handler
    signal.signal(signal.SIGINT, signal_handler)
    try:
        signal.signal(signal.SIGTERM, signal_handler)
    except AttributeError:
        pass  # SIGTERM not on Windows

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1)
    server_socket.settimeout(1.0)  # 🔹 Allow loop to periodically check for shutdown
    print(f"[SERVER] Listening on port {port} (Ctrl+C to stop)...\n")

    try:
        while not shutdown_requested:
            try:
                client_socket, client_addr = server_socket.accept()
            except socket.timeout:
                continue  # No connection yet, loop again and check shutdown flag
            except OSError:
                break  # Socket closed externally

            with client_socket:
                print(f"[SERVER] Connection from {client_addr}")
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                print(f"[SERVER] Sending timestamp: {timestamp}")
                client_socket.sendall(timestamp.encode("utf-8"))

    except Exception as e:
        print(f"[SERVER] Error: {e}")

    finally:
        if server_socket:
            try:
                server_socket.close()
            except Exception:
                pass
        print("[SERVER] Shutdown complete.")


if __name__ == "__main__":
    main()