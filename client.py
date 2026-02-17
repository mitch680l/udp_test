import socket
import sys
from protocol import (
    MAX_RECV_SIZE, MAX_PAYLOAD_SIZE, RETRANSMIT_TIMEOUT_S,
    TYPE_DATA, TYPE_ACK, TYPE_NACK,
    make_packet, parse_packet, type_name,
)


def send_with_rdt(sock, server_addr, seq, payload, flags=0,
                  timeout=RETRANSMIT_TIMEOUT_S):
    packet = make_packet(TYPE_DATA, seq, payload, flags=flags)
    attempt = 0

    while True:
        attempt += 1
        print(f"[CLIENT] TX seq={seq} len={len(payload)} "
              f"flags=0x{flags:02X} attempt={attempt}")

        sock.sendto(packet, server_addr)
        sock.settimeout(timeout)

        try:
            raw, _ = sock.recvfrom(MAX_RECV_SIZE)
        except socket.timeout:
            print(f"[CLIENT] Timeout ({timeout}s), retransmitting")
            continue

        resp, _, resp_valid = parse_packet(raw)

        if resp is None or not resp_valid:
            print(f"[CLIENT] Corrupted response, retransmitting")
            continue

        rtype = type_name(resp['type'])
        print(f"[CLIENT] Got {rtype} seq={resp['seq']}")

        if resp['type'] == TYPE_ACK:
            print(f"[CLIENT] Delivered")
            return True
        elif resp['type'] == TYPE_NACK:
            print(f"[CLIENT] NACK, retransmitting")
            continue
        else:
            print(f"[CLIENT] Unexpected type, retransmitting")
            continue


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <server_ip> <server_port> [message]")
        sys.exit(1)

    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    message = ' '.join(sys.argv[3:]) if len(sys.argv) > 3 else "Hello via satellite!"

    data = message.encode('utf-8')
    if len(data) > MAX_PAYLOAD_SIZE:
        print(f"[CLIENT] Message too large ({len(data)}B, max {MAX_PAYLOAD_SIZE})")
        sys.exit(1)

    print(f"[CLIENT] Target: {server_ip}:{server_port}")
    print(f"[CLIENT] Message: {len(data)}B")
    print(f"[CLIENT] Retransmit timeout: {RETRANSMIT_TIMEOUT_S}s\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        send_with_rdt(sock, (server_ip, server_port), 0, data)
        print(f"\n[CLIENT] Message delivered.")
    finally:
        sock.close()


if __name__ == '__main__':
    main()
