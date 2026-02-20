import socket
import sys
import signal
import time
from protocol import (
    HEADER_SIZE, CHECKSUM_SIZE, MAX_RECV_SIZE,
    parse_packet, make_ack, make_nack,
    TYPE_DATA, type_name, flag_name, decode_payload,
    FLAG_ID, crc16_ccitt,
)
from mqtt_bridge import MQTTBridge

SESSION_TIMEOUT_S = 30000 

shutdown = False


def signal_handler(sig, frame):
    global shutdown
    print("\n[SERVER] Shutting down...")
    shutdown = True


def cleanup_sessions(sessions, timeout):
    now = time.time()
    expired = [k for k, v in sessions.items() if now - v['last_seen'] > timeout]
    names = []
    for k in expired:
        print(f"[SERVER] Session expired: {sessions[k]['name']} ({k})")
        names.append(sessions[k]['name'])
        del sessions[k]
    return names


def session_label(sessions, addr):
    s = sessions.get(addr[0])
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

    bridge = MQTTBridge(udp_send_fn=lambda addr, pkt: sock.sendto(pkt, addr))
    bridge.start()

    try:
        while not shutdown:
            if time.time() - last_cleanup > 30:
                for name in cleanup_sessions(sessions, timeout):
                    bridge.deregister_device(name)
                last_cleanup = time.time()

            try:
                raw, addr = sock.recvfrom(MAX_RECV_SIZE)
            except socket.timeout:
                continue
            except OSError:
                break

            header, payload, valid = parse_packet(raw)

            if header is None or payload is None:
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
                data_end = HEADER_SIZE + header['payload_len']
                expected_crc = crc16_ccitt(raw[:data_end])
                actual_crc = int.from_bytes(raw[data_end:data_end + CHECKSUM_SIZE], 'big')
                print(f"[SERVER] [{label}] Checksum FAILED, sending NACK")
                print(f"[SERVER] [{label}]   expected=0x{expected_crc:04X} got=0x{actual_crc:04X}")
                print(f"[SERVER] [{label}]   raw={raw.hex()}")
                sock.sendto(make_nack(header['seq']), addr)
                continue

            sock.sendto(make_ack(header['seq']), addr)

            if addr[0] in sessions:
                sessions[addr[0]]['last_seen'] = time.time()

            result = decode_payload(header['flags'], payload)

            if header['flags'] == FLAG_ID and 'name' in result:
                sessions[addr[0]] = {
                    'name': result['name'],
                    'client_ip': result.get('ip', addr[0]),
                    'client_port': result.get('port', str(addr[1])),
                    'last_seen': time.time(),
                }
                label = session_label(sessions, addr)
                bridge.register_device(result['name'], addr)
            elif addr[0] in sessions:
                bridge.update_addr(sessions[addr[0]]['name'], addr)

            client_id = sessions[addr[0]]['name'] if addr[0] in sessions else f"{addr[0]}:{addr[1]}"
            bridge.publish(client_id, header['flags'], payload)

            print(f"[SERVER] [{label}] {result['display']}")

    finally:
        bridge.stop()
        sock.close()
        print(f"[SERVER] Socket closed. Active sessions: {len(sessions)}")


if __name__ == '__main__':
    main()
