import json
import os
import threading
import paho.mqtt.client as mqtt

from protocol import (
    FLAG_GPS, FLAG_ID, FLAG_GEN, FLAG_SENS, FLAG_CMD,
    TYPE_DATA, make_packet, decode_id,
)


MQTT_HOST      = "44.209.5.53"
MQTT_PORT      = 8883
MQTT_USERNAME  = "admin"
MQTT_PASSWORD  = "Kalscott123"
MQTT_TLS       = True
MQTT_CA_CERT   = "~/autobuilder/server_auth/42/ca.crt"  
MQTT_CERTFILE  = "~/autobuilder/server_auth/42/public.crt"  
MQTT_KEYFILE   = "~/autobuilder/server_auth/42/public.key"  
MQTT_CLIENT_ID = "ntn-udp-gateway"
MQTT_QOS       = 1


UPLINK_MAP = {
    FLAG_GPS:  ("{client_id}/gps",  None),
    FLAG_ID:   ("{client_id}/id",   None),
    FLAG_GEN:  ("{client_id}/gen",  None),
    FLAG_SENS: ("{client_id}/sensor", None),
}


DOWNLINK_MAP = [
    ("{client_id}/command", FLAG_CMD, None),
]



def _serialise(data) -> bytes | None:
    if data is None:
        return None
    if isinstance(data, bytes):
        return json.dumps({"hex": data.hex(), "len": len(data)}).encode()
    if isinstance(data, dict):
        return json.dumps(data).encode()
    if isinstance(data, str):
        return data.encode()
    return bytes(data)


class MQTTBridge:
    def __init__(self, udp_send_fn):
        self._udp_send_fn = udp_send_fn
        self._lock = threading.Lock()
        self._addr_map = {}
        self._seq_map  = {}   

        self._client = mqtt.Client(client_id=MQTT_CLIENT_ID)
        if MQTT_USERNAME:
            self._client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
        if MQTT_TLS:
            self._client.tls_set(
                ca_certs=os.path.expanduser(MQTT_CA_CERT)  if MQTT_CA_CERT  else None,
                certfile=os.path.expanduser(MQTT_CERTFILE) if MQTT_CERTFILE else None,
                keyfile =os.path.expanduser(MQTT_KEYFILE)  if MQTT_KEYFILE  else None,
            )

        self._client.on_connect    = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.on_message    = self._on_message
        self._client.reconnect_delay_set(min_delay=1, max_delay=30)


    def start(self):
        self._client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)
        self._client.loop_start()

    def stop(self):
        self._client.loop_stop()
        self._client.disconnect()


    def register_device(self, client_id: str, addr: tuple):
        with self._lock:
            self._addr_map[client_id] = addr
            if client_id not in self._seq_map:
                self._seq_map[client_id] = 0
        self._subscribe_device(client_id)
        self._client.publish(f"{client_id}/mode", "UDP Bridge Active", qos=MQTT_QOS)
        print(f"[MQTT] Registered {client_id} @ {addr[0]}:{addr[1]}")

    def update_addr(self, client_id: str, addr: tuple):
        with self._lock:
            self._addr_map[client_id] = addr

    def deregister_device(self, client_id: str):
        """Unsubscribe from all downlink topics for this device and remove
        its state. Called when the server-side session expires."""
        with self._lock:
            self._addr_map.pop(client_id, None)
            self._seq_map.pop(client_id, None)
        self._client.publish(f"{client_id}/mode", "UDP Bridge Session Timeout", qos=MQTT_QOS)
        for topic_tmpl, *_ in DOWNLINK_MAP:
            topic = topic_tmpl.format(client_id=client_id)
            self._client.unsubscribe(topic)
            print(f"[MQTT] Unsubscribed ← {topic} ({client_id} expired)")

    def publish(self, client_id: str, flags: int, payload: bytes):
        if flags not in UPLINK_MAP:
            return
        topic_tmpl, processor = UPLINK_MAP[flags]
        topic = topic_tmpl.format(client_id=client_id)

        if flags == FLAG_ID and processor is None:
            result = decode_id(payload)
            result.pop('display', None)
            data = _serialise(result)
        elif processor is not None:
            data = _serialise(processor(payload))
        else:
            data = _serialise(payload)

        if data is None:
            return

        self._client.publish(topic, data, qos=MQTT_QOS)
        print(f"[UDP→MQTT] {topic}  ({len(data)}B)")

    def _subscribe_device(self, client_id: str):
        for topic_tmpl, _flag, _proc in DOWNLINK_MAP:
            topic = topic_tmpl.format(client_id=client_id)
            self._client.subscribe(topic, qos=MQTT_QOS)
            print(f"[MQTT] Subscribed ← {topic}")

    def _on_message(self, client, userdata, msg):
        topic   = msg.topic
        payload = msg.payload

        with self._lock:
            addr_map_copy = dict(self._addr_map)

        for client_id, addr in addr_map_copy.items():
            for topic_tmpl, flag, processor in DOWNLINK_MAP:
                if topic != topic_tmpl.format(client_id=client_id):
                    continue

                if processor is not None:
                    payload = processor(payload)
                if payload is None:
                    return

                if len(payload) > 128:
                    print(f"[MQTT→UDP] {topic}: payload too large ({len(payload)}B), dropping")
                    return

                with self._lock:
                    seq = self._seq_map.get(client_id, 0)
                    self._seq_map[client_id] = seq ^ 1

                pkt = make_packet(TYPE_DATA, seq, payload, flags=flag)
                self._udp_send_fn(addr, pkt)
                print(f"[MQTT→UDP] {topic} → {client_id} @ {addr[0]}:{addr[1]}"
                      f"  flag=0x{flag:02X} seq={seq} len={len(payload)}")
                return

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            print(f"[MQTT] Connected to {MQTT_HOST}:{MQTT_PORT}")
            with self._lock:
                devices = list(self._addr_map.keys())
            for client_id in devices:
                self._subscribe_device(client_id)
        else:
            print(f"[MQTT] Connection failed (rc={rc})")

    def _on_disconnect(self, client, userdata, rc):
        if rc != 0:
            print(f"[MQTT] Unexpected disconnect (rc={rc}), will reconnect")
