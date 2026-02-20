import struct

HEADER_SIZE = 8
CHECKSUM_SIZE = 2
MAX_PAYLOAD_SIZE = 128
MIN_PAYLOAD_SIZE = 1
RETRANSMIT_TIMEOUT_S = 25
MAX_RECV_SIZE = HEADER_SIZE + MAX_PAYLOAD_SIZE + CHECKSUM_SIZE + 64

TYPE_DATA = ord('D')
TYPE_ACK = ord('A')
TYPE_NACK = ord('N')

HEADER_FMT = '!BBHB3s'


FLAG_UNKNOWN = 0x00
FLAG_ID = 0x02
FLAG_GPS = 0x01
FLAG_GEN = 0x03


def crc16_ccitt(data: bytes) -> int:
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc >> 1) ^ 0x8408) if crc & 1 else crc >> 1
    return crc


def make_packet(pkt_type, seq, payload, flags=0):
    payload_len = len(payload)
    if payload_len > MAX_PAYLOAD_SIZE:
        raise ValueError(f"payload too large: {payload_len} > {MAX_PAYLOAD_SIZE}")

    header = struct.pack(HEADER_FMT, pkt_type, seq, payload_len, flags, b'\x00\x00\x00')
    crc = crc16_ccitt(header + payload)
    return header + payload + struct.pack('!H', crc)


def parse_packet(raw):
    if len(raw) < HEADER_SIZE + CHECKSUM_SIZE:
        return None, None, False

    hdr_bytes = raw[:HEADER_SIZE]
    pkt_type, seq, payload_len, flags, _reserved = struct.unpack(HEADER_FMT, hdr_bytes)

    expected_len = HEADER_SIZE + payload_len + CHECKSUM_SIZE
    if len(raw) != expected_len:
        return None, None, False

    pay_bytes = raw[HEADER_SIZE:HEADER_SIZE + payload_len]
    crc_bytes = raw[HEADER_SIZE + payload_len:]

    expected = crc16_ccitt(hdr_bytes + pay_bytes)
    actual = struct.unpack('!H', crc_bytes)[0]
    valid = expected == actual

    header = {
        'type': pkt_type,
        'seq': seq,
        'payload_len': payload_len,
        'flags': flags,
    }
    return header, pay_bytes, valid


def make_ack(seq):
    return make_packet(TYPE_ACK, seq, b'')


def make_nack(seq):
    return make_packet(TYPE_NACK, seq, b'')


def type_name(pkt_type):
    return {TYPE_DATA: 'DATA', TYPE_ACK: 'ACK', TYPE_NACK: 'NACK'}.get(pkt_type, '???')




def decode_id(payload):
    try:
        text = payload.decode('utf-8')
        parts = text.split(',')
        if len(parts) >= 3:
            ip = parts[0]
            port = parts[1]
            name = ','.join(parts[2:])
            return {'ip': ip, 'port': port, 'name': name, 'display': f"ID {name} ({ip}:{port})"}
        return {'display': f"ID (malformed): {text}"}
    except UnicodeDecodeError:
        return {'display': f"ID (binary): {payload.hex()}"}


def decode_gps(payload):
    try:
        text = payload.decode('utf-8')
        return {'display': f"GPS: {text}"}
    except UnicodeDecodeError:
        return {'display': f"GPS: (hex) {payload.hex()}"}


def decode_unknown(payload):
    try:
        text = payload.decode('utf-8')
        return {'display': f"[Unknown] {text}"}
    except UnicodeDecodeError:
        return {'display': f"[Unknown] (hex) {payload.hex()}"}


MESSAGE_DECODERS = {
    FLAG_ID:  ("ID",  decode_id),
    FLAG_GPS: ("GPS", decode_gps),
}


def decode_payload(flags, payload):
    if flags in MESSAGE_DECODERS:
        label, decoder = MESSAGE_DECODERS[flags]
        return decoder(payload)
    return decode_unknown(payload)


def flag_name(flags):
    if flags in MESSAGE_DECODERS:
        return MESSAGE_DECODERS[flags][0]
    return f"Unknown(0x{flags:02X})"
