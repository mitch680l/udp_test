import socket
import sys
from protocol import (
    PACKET_SIZE, RETRANSMIT_TIMEOUT_S, MAX_MESSAGE_SIZE,
    TYPE_DATA, TYPE_ACK, TYPE_NACK,
    make_packet, parse_packet, fragment_message, type_name,
)


def send_with_rdt(sock, server_addr, seq, frag_idx, frag_total, payload,
                  timeout=RETRANSMIT_TIMEOUT_S):
    packet = make_packet(TYPE_DATA, seq, frag_idx, frag_total, payload)
    attempt = 0

    while True:
        attempt += 1
        print(f"[CLIENT] Sending frag={frag_idx}/{frag_total} seq={seq} "
              f"len={len(payload)} attempt={attempt}")

        sock.sendto(packet, server_addr)
        sock.settimeout(timeout)

        try:
            raw, _ = sock.recvfrom(PACKET_SIZE + 64)
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
            print(f"[CLIENT] Fragment {frag_idx} delivered")
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
    if len(data) > MAX_MESSAGE_SIZE:
        print(f"[CLIENT] Message too large ({len(data)}B, max {MAX_MESSAGE_SIZE})")
        sys.exit(1)

    chunks = fragment_message(data)
    frag_total = len(chunks)

    print(f"[CLIENT] Target: {server_ip}:{server_port}")
    print(f"[CLIENT] Message: {len(data)}B, {frag_total} fragment(s)")
    print(f"[CLIENT] Retransmit timeout: {RETRANSMIT_TIMEOUT_S}s\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    seq = 0
    try:
        for i, chunk in enumerate(chunks):
            send_with_rdt(sock, (server_ip, server_port), seq, i, frag_total, chunk)
            seq ^= 1
        print(f"\n[CLIENT] All {frag_total} fragment(s) delivered.")
    finally:
        sock.close()


if __name__ == '__main__':
    main()
