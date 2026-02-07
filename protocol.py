import struct

HEADER_SIZE = 8
PAYLOAD_SIZE = 50
CHECKSUM_SIZE = 2
PACKET_SIZE = HEADER_SIZE + PAYLOAD_SIZE + CHECKSUM_SIZE

MAX_MESSAGE_SIZE = 1100
MAX_FRAGMENTS = (MAX_MESSAGE_SIZE + PAYLOAD_SIZE - 1) // PAYLOAD_SIZE
RETRANSMIT_TIMEOUT_S = 25 * 60

TYPE_DATA = ord('D')
TYPE_ACK = ord('A')
TYPE_NACK = ord('N')

HEADER_FMT = '!BBBBHBB'


def crc16_ccitt(data: bytes) -> int:
    crc = 0x0000
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc


def make_packet(pkt_type, seq, frag_idx, frag_total, payload, flags=0):
    if len(payload) > PAYLOAD_SIZE:
        raise ValueError(f"payload too large: {len(payload)} > {PAYLOAD_SIZE}")

    payload_len = len(payload)
    padded = payload.ljust(PAYLOAD_SIZE, b'\x00')
    header = struct.pack(HEADER_FMT, pkt_type, seq, frag_idx, frag_total,
                         payload_len, flags, 0)
    crc = crc16_ccitt(header + padded)
    return header + padded + struct.pack('!H', crc)


def parse_packet(raw):
    if len(raw) != PACKET_SIZE:
        return None, None, False

    hdr_bytes = raw[:HEADER_SIZE]
    pay_bytes = raw[HEADER_SIZE:HEADER_SIZE + PAYLOAD_SIZE]
    crc_bytes = raw[HEADER_SIZE + PAYLOAD_SIZE:]

    expected = crc16_ccitt(hdr_bytes + pay_bytes)
    actual = struct.unpack('!H', crc_bytes)[0]
    valid = expected == actual

    pkt_type, seq, frag_idx, frag_total, payload_len, flags, _ = \
        struct.unpack(HEADER_FMT, hdr_bytes)

    header = {
        'type': pkt_type,
        'seq': seq,
        'frag_idx': frag_idx,
        'frag_total': frag_total,
        'payload_len': payload_len,
        'flags': flags,
    }
    return header, pay_bytes[:payload_len], valid


def make_ack(seq):
    return make_packet(TYPE_ACK, seq, 0, 0, b'')


def make_nack(seq):
    return make_packet(TYPE_NACK, seq, 0, 0, b'')


def fragment_message(data):
    if len(data) > MAX_MESSAGE_SIZE:
        raise ValueError(f"message too large: {len(data)} > {MAX_MESSAGE_SIZE}")
    if not data:
        return [b'']
    return [data[i:i + PAYLOAD_SIZE] for i in range(0, len(data), PAYLOAD_SIZE)]


def type_name(pkt_type):
    return {TYPE_DATA: 'DATA', TYPE_ACK: 'ACK', TYPE_NACK: 'NACK'}.get(pkt_type, '???')
