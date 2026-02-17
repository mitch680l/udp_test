import socket
import random
import string
import sys
from protocol import (
    MAX_PAYLOAD_SIZE, FLAG_ID, FLAG_GPS, FLAG_UNKNOWN,
)
from client import send_with_rdt


def random_text(length):
    return ''.join(random.choices(string.ascii_letters + string.digits + ' ', k=length))


def random_name():
    prefixes = ["Tracker", "Sensor", "Device", "Beacon", "Node", "Probe"]
    return random.choice(prefixes) + "-" + ''.join(random.choices(string.digits, k=3))


def random_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def make_id_payload():
    ip = random_ip()
    port = str(random.randint(1024, 65535))
    name = random_name()
    return f"{ip},{port},{name}".encode('utf-8')


def make_gps_payload():
    lat = round(random.uniform(-90, 90), 6)
    lon = round(random.uniform(-180, 180), 6)
    alt = round(random.uniform(0, 12000), 1)
    return f"{lat},{lon},{alt}".encode('utf-8')


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
        id_payload = make_id_payload()
        print(f"\n{'='*50}")
        print(f"[TEST 0] ID message: {id_payload.decode()}")
        print(f"{'='*50}")
        send_with_rdt(sock, (server_ip, server_port), seq, id_payload, flags=FLAG_ID)
        seq ^= 1

        for i in range(count):
            choice = random.choice(['gps', 'text', 'unknown'])

            if choice == 'gps':
                payload = make_gps_payload()
                flags = FLAG_GPS
                kind = "GPS"
            elif choice == 'unknown':
                length = random.randint(1, 200)
                payload = random_text(length).encode('utf-8')
                flags = FLAG_UNKNOWN
                kind = "Unknown(0x00)"
            else:
                length = random.randint(1, 200)
                payload = random_text(length).encode('utf-8')
                flags = FLAG_UNKNOWN
                kind = "Text(no flag)"

            print(f"\n{'='*50}")
            print(f"[TEST {i+1}/{count}] {kind} | {len(payload)}B")
            print(f"  Payload: {payload[:60]}...")
            print(f"{'='*50}")

            send_with_rdt(sock, (server_ip, server_port), seq, payload, flags=flags)
            seq ^= 1

            print(f"[TEST {i+1}/{count}] Delivered")
    finally:
        sock.close()

    print(f"\nAll {count + 1} test messages sent (1 ID + {count} data).")


if __name__ == '__main__':
    main()
