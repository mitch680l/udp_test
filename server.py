import socket
import sys
import signal
from protocol import (
    PACKET_SIZE, parse_packet, make_ack, make_nack,
    TYPE_DATA, type_name,
    HEADER_SIZE, PAYLOAD_SIZE, CHECKSUM_SIZE,
)

shutdown = False


def signal_handler(sig, frame):
    global shutdown
    print("\n[SERVER] Shutting down...")
    shutdown = True


def main():
    global shutdown
    signal.signal(signal.SIGINT, signal_handler)

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', port))
    sock.settimeout(1.0)

    assigned_port = sock.getsockname()[1]
    print(f"[SERVER] Listening on port {assigned_port}")
    print(f"[SERVER] Packet: {PACKET_SIZE}B (hdr={HEADER_SIZE} pay={PAYLOAD_SIZE} crc={CHECKSUM_SIZE})")
    print(f"[SERVER] Waiting for data...\n")

    reassembly = {}
    expected_frags = {}

    try:
        while not shutdown:
            try:
                raw, addr = sock.recvfrom(PACKET_SIZE + 64)
            except socket.timeout:
                continue
            except OSError:
                break

            header, payload, valid = parse_packet(raw)

            if header is None:
                print(f"[SERVER] Malformed packet from {addr} (size={len(raw)})")
                continue

            ptype = type_name(header['type'])
            print(f"[SERVER] [{addr}] {ptype} seq={header['seq']} "
                  f"frag={header['frag_idx']}/{header['frag_total']} "
                  f"len={header['payload_len']} crc={'OK' if valid else 'FAIL'}")

            if header['type'] != TYPE_DATA:
                continue

            if not valid:
                print(f"[SERVER] [{addr}] Checksum FAILED, sending NACK")
                sock.sendto(make_nack(header['seq']), addr)
                continue

            print(f"[SERVER] [{addr}] Checksum OK, sending ACK")
            sock.sendto(make_ack(header['seq']), addr)

            key = addr
            if key not in reassembly:
                reassembly[key] = {}
                expected_frags[key] = header['frag_total']

            reassembly[key][header['frag_idx']] = payload

            if len(reassembly[key]) == expected_frags[key]:
                full_msg = b''
                for i in range(expected_frags[key]):
                    full_msg += reassembly[key].get(i, b'')

                print(f"\n[SERVER] === COMPLETE MESSAGE from {addr} ===")
                try:
                    print(f"[SERVER] {full_msg.decode('utf-8')}")
                except UnicodeDecodeError:
                    print(f"[SERVER] (hex) {full_msg.hex()}")
                print(f"[SERVER] ===================================\n")

                del reassembly[key]
                del expected_frags[key]
    finally:
        sock.close()
        print("[SERVER] Socket closed.")


if __name__ == '__main__':
    main()
