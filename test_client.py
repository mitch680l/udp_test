import socket
import random
import string
import sys
from protocol import (
    PACKET_SIZE, PAYLOAD_SIZE, MAX_MESSAGE_SIZE, RETRANSMIT_TIMEOUT_S,
    TYPE_DATA, TYPE_ACK, TYPE_NACK,
    make_packet, parse_packet, fragment_message, type_name,
)
from client import send_with_rdt


def random_text(length):
    return ''.join(random.choices(string.ascii_letters + string.digits + ' ', k=length))


def random_bytes(length):
    return bytes(random.randint(0, 255) for _ in range(length))


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <server_ip> <server_port> [count]")
        sys.exit(1)

    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 5

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0

    try:
        for i in range(count):
            # randomly pick text or binary payload
            if random.choice([True, False]):
                length = random.randint(1, MAX_MESSAGE_SIZE)
                data = random_text(length).encode('utf-8')[:MAX_MESSAGE_SIZE]
                kind = "text"
            else:
                length = random.randint(1, MAX_MESSAGE_SIZE)
                data = random_bytes(length)
                kind = "binary"

            chunks = fragment_message(data)
            frag_total = len(chunks)

            print(f"\n{'='*50}")
            print(f"[TEST {i+1}/{count}] {kind} | {len(data)}B | {frag_total} fragment(s)")
            print(f"  Preview: {data[:40]}...")
            print(f"{'='*50}")

            for fi, chunk in enumerate(chunks):
                send_with_rdt(sock, (server_ip, server_port), seq, fi, frag_total, chunk)
                seq ^= 1

            print(f"[TEST {i+1}/{count}] Delivered successfully")
    finally:
        sock.close()

    print(f"\nAll {count} test messages sent.")


if __name__ == '__main__':
    main()
