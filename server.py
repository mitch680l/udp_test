import socket
import sys
import signal
import time
from protocol import (
    HEADER_SIZE, CHECKSUM_SIZE, MAX_RECV_SIZE,
    parse_packet, make_ack, make_nack,
    TYPE_DATA, type_name, flag_name, decode_payload,
    FLAG_ID,
)

SESSION_TIMEOUT_S = 30000 

shutdown = False


def signal_handler(sig, frame):
    global shutdown
    print("\n[SERVER] Shutting down...")
    shutdown = True


def cleanup_sessions(sessions, timeout):
    now = time.time()
    expired = [k for k, v in sessions.items() if now - v['last_seen'] > timeout]
    for k in expired:
        print(f"[SERVER] Session expired: {sessions[k]['name']} ({k[0]}:{k[1]})")
        del sessions[k]


def session_label(sessions, addr):
    s = sessions.get(addr)
    if s:
        return f"{s['name']}@{addr[0]}:{addr[1]}"
    return f"{addr[0]}:{addr[1]}"


def main():
    global shutdown
    signal.signal(signal.SIGINT, signal_handler)

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else SESSION_TIMEOUT_S

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', port))
    sock.settimeout(1.0)

    assigned_port = sock.getsockname()[1]
    print(f"[SERVER] Listening on port {assigned_port}")
    print(f"[SERVER] Header={HEADER_SIZE}B  CRC={CHECKSUM_SIZE}B  Variable payload")
    print(f"[SERVER] Session timeout: {timeout}s")
    print(f"[SERVER] Waiting for data...\n")

    sessions = {}  
    last_cleanup = time.time()

    try:
        while not shutdown:
            if time.time() - last_cleanup > 30:
                cleanup_sessions(sessions, timeout)
                last_cleanup = time.time()

            try:
                raw, addr = sock.recvfrom(MAX_RECV_SIZE)
            except socket.timeout:
                continue
            except OSError:
                break

            header, payload, valid = parse_packet(raw)

            if header is None:
                print(f"[SERVER] Malformed packet from {addr} (size={len(raw)})")
                continue

            label = session_label(sessions, addr)
            ptype = type_name(header['type'])
            fname = flag_name(header['flags'])

            print(f"[SERVER] [{label}] {ptype} seq={header['seq']} "
                  f"flags={fname} len={header['payload_len']} "
                  f"crc={'OK' if valid else 'FAIL'}")

            if header['type'] != TYPE_DATA:
                continue

            if not valid:
                print(f"[SERVER] [{label}] Checksum FAILED, sending NACK")
                sock.sendto(make_nack(header['seq']), addr)
                continue

            sock.sendto(make_ack(header['seq']), addr)


            if addr in sessions:
                sessions[addr]['last_seen'] = time.time()


            result = decode_payload(header['flags'], payload)


            if header['flags'] == FLAG_ID and 'name' in result:
                sessions[addr] = {
                    'name': result['name'],
                    'client_ip': result.get('ip', addr[0]),
                    'client_port': result.get('port', str(addr[1])),
                    'last_seen': time.time(),
                }
                label = session_label(sessions, addr)

            print(f"[SERVER] [{label}] {result['display']}")

    finally:
        sock.close()
        print(f"[SERVER] Socket closed. Active sessions: {len(sessions)}")


if __name__ == '__main__':
    main()
