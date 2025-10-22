import struct
import uuid
import time
import threading
from protocol import pack_response_header

from protocol import (
    RES_ERROR,
    RES_CLIENTS_LIST,
    RES_PUBLIC_KEY,
    RES_MESSAGE_RECEIVED,
    RES_WAITING_MESSAGES,
    RES_REGISTRATION_OK,
    UUID_SIZE,
    NAME_SIZE,
    PUBKEY_SIZE,
    CONTENT_SIZE,
    MSG_TYPE_SIZE,
    MSG_ID_SIZE,
    MAX_PAYLOAD_SIZE
)

VERBOSE = True
def log(msg):
    if VERBOSE:
        print(msg)

# ===== Global State =====
STATE = {
    "clients": {},
    "pending_messages": {},
}

# global thread lock
STATE_LOCK = threading.Lock()


def send_response(conn, code, payload: bytes = b""):
    try:
        if code == RES_ERROR:
            payload = b""
        header = pack_response_header(code, len(payload))
        conn.sendall(header)
        if payload:
            conn.sendall(payload)
        log(f"[SEND_RESPONSE] Code={code}, PayloadSize={len(payload)} sent.")
    except Exception as e:
        log(f"[SEND_RESPONSE] Failed to send ({e})")


# ===== 600 – Register =====
def handle_register(conn, payload: bytes):
    try:
        if len(payload) != NAME_SIZE + PUBKEY_SIZE:
            send_response(conn, RES_ERROR)
            return

        name_bytes = payload[:NAME_SIZE]
        name = name_bytes.split(b'\x00', 1)[0].decode('ascii', errors='ignore')

        if not all(32 <= b < 127 for b in name.encode('ascii', 'ignore')):
            send_response(conn, RES_ERROR)
            return

        with STATE_LOCK:
            for c in STATE["clients"].values():
                if c["name"] == name:
                    send_response(conn, RES_ERROR)
                    return

            pubkey = payload[NAME_SIZE:NAME_SIZE + PUBKEY_SIZE]
            client_id = uuid.uuid4().bytes
            client_id_hex = client_id.hex()

            STATE["clients"][client_id_hex] = {
                "name": name,
                "pubkey": pubkey,
                "last_seen": time.time(),
            }

        send_response(conn, RES_REGISTRATION_OK, client_id)
        log(f"[REGISTER] {name} registered ({client_id_hex[:8]})")

    except Exception as e:
        log(f"[REGISTER] Exception: {e}")
        send_response(conn, RES_ERROR)


# ===== 601 – Get Client List =====
def handle_get_clients_list(conn, requester_hex):
    try:
        with STATE_LOCK:
            visible = [
                (cid_hex, info)
                for cid_hex, info in STATE["clients"].items()
                if cid_hex != requester_hex
            ]
            # Update last_seen only for valid requester
            if requester_hex in STATE["clients"]:
                STATE["clients"][requester_hex]["last_seen"] = time.time()

        payload = b''
        for cid_hex, info in visible:
            cid_bytes = bytes.fromhex(cid_hex)
            name_bytes = info["name"].encode('ascii')
            name_padded = name_bytes + b'\x00' * (NAME_SIZE - len(name_bytes))
            payload += cid_bytes + name_padded

        send_response(conn, RES_CLIENTS_LIST, payload)
        log(f"[CLIENTS LIST] Sent {len(visible)} entries.")

    except Exception as e:
        log(f"[CLIENTS LIST] Exception: {e}")
        send_response(conn, RES_ERROR)


# ===== 602 – Public Key =====
def handle_get_public_key(conn, payload: bytes, requester_hex):
    try:
        if len(payload) != UUID_SIZE:
            send_response(conn, RES_ERROR)
            return

        cid_hex = payload.hex()
        with STATE_LOCK: 
            target_info = STATE["clients"].get(cid_hex)
            if not target_info:
                send_response(conn, RES_ERROR)
                return

            pubkey = target_info["pubkey"]
            
            # Update last_seen for requester
            if requester_hex in STATE["clients"]:
                STATE["clients"][requester_hex]["last_seen"] = time.time()

        payload_out = bytes.fromhex(cid_hex) + pubkey
        send_response(conn, RES_PUBLIC_KEY, payload_out)
        log(f"[PUBLIC KEY] Sent key for {target_info['name']}")

    except Exception as e:
        log(f"[PUBLIC KEY] Exception: {e}")
        send_response(conn, RES_ERROR)


# ===== 603 – Send Message =====
def handle_send_message(conn, payload: bytes, header):
    try:
        min_size = UUID_SIZE + MSG_TYPE_SIZE + CONTENT_SIZE
        if len(payload) < min_size:
            send_response(conn, RES_ERROR)
            return

        to_uuid = payload[0:UUID_SIZE].hex()
        msg_type = payload[UUID_SIZE]
        content_size = int.from_bytes(
            payload[UUID_SIZE + MSG_TYPE_SIZE : UUID_SIZE + MSG_TYPE_SIZE + CONTENT_SIZE], "little")
        content = payload[min_size:]

        if len(content) != content_size or content_size > MAX_PAYLOAD_SIZE:
            send_response(conn, RES_ERROR)
            return

        from_uuid = header["client_id"]

        with STATE_LOCK:
            if to_uuid not in STATE["clients"]:
                send_response(conn, RES_ERROR)
                return

            STATE["pending_messages"].setdefault(to_uuid, [])
            message_id = len(STATE["pending_messages"][to_uuid])
            STATE["pending_messages"][to_uuid].append({
                "from": from_uuid,
                "type": msg_type,
                "content": content
            })

            # Update sender last_seen
            if from_uuid in STATE["clients"]:
                STATE["clients"][from_uuid]["last_seen"] = time.time()

        response_payload = bytes.fromhex(to_uuid) + message_id.to_bytes(4, "little")
        send_response(conn, RES_MESSAGE_RECEIVED, response_payload)
        log(f"[SEND MESSAGE] #{message_id} {from_uuid[:8]} → {to_uuid[:8]}")

    except Exception as e:
        log(f"[SEND MESSAGE] Exception: {e}")
        send_response(conn, RES_ERROR)


# ===== 604 – Get Waiting Messages =====
def handle_get_waiting_messages(conn, payload: bytes, header):
    try:
        to_uuid = header["client_id"]

        with STATE_LOCK:
            if to_uuid not in STATE["clients"]:
                send_response(conn, RES_ERROR)
                return

            messages = STATE["pending_messages"].get(to_uuid, [])
            STATE["clients"][to_uuid]["last_seen"] = time.time()

        if not messages:
            send_response(conn, RES_WAITING_MESSAGES, b"")
            log(f"[GET WAITING] No pending messages for {to_uuid[:8]}")
            return

        payload_bytes = bytearray()
        for msg_id, msg in enumerate(messages):
            from_uuid = msg["from"]
            msg_type = msg["type"]
            content = msg["content"]
            msg_size = len(content)

            if msg_size > MAX_PAYLOAD_SIZE:
                continue

            payload_bytes += bytes.fromhex(from_uuid)
            payload_bytes += msg_id.to_bytes(MSG_ID_SIZE, "little")
            payload_bytes += msg_type.to_bytes(MSG_TYPE_SIZE, "little")
            payload_bytes += msg_size.to_bytes(CONTENT_SIZE, "little")
            payload_bytes += content

        # Clear messages atomically
        with STATE_LOCK:
            STATE["pending_messages"][to_uuid] = []

        send_response(conn, RES_WAITING_MESSAGES, bytes(payload_bytes))
        log(f"[GET WAITING] Sent {len(messages)} messages to {to_uuid[:8]}")

    except Exception as e:
        log(f"[GET WAITING] Exception: {e}")
        send_response(conn, RES_ERROR)
