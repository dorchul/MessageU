import struct
import uuid

from protocol import (
    RES_ERROR,
    RES_CLIENTS_LIST,
    RES_MESSAGE_RECEIVED,
    RES_WAITING_MESSAGES,
    RES_REGISTRATION_OK,
    MSG_TYPE_REQUEST_SYM,
    MSG_TYPE_SEND_SYM,
    MSG_TYPE_TEXT,
    MSG_TYPE_FILE,
)

# ===== Global State =====
# Holds clients and their pending messages
STATE = {
    "clients": {},   # client_id(hex) → {"name": str, "pubkey": bytes}
    "pending": {}    # to_client_id(hex) → [ (from_id_hex, type, content_bytes) ]
}

def send_response(conn, code, payload: bytes):
    header = struct.pack("<BHI", 1, code, len(payload))
    conn.sendall(header)
    if payload:
        conn.sendall(payload)
    print(f"[SEND_RESPONSE] Code={code}, PayloadSize={len(payload)} sent.")

def handle_register(conn, payload):
    if len(payload) < 1 + 160:
        send_response(conn, RES_ERROR, b'invalid register payload')
        return

    name_len = payload[0]
    name = payload[1:1 + name_len].decode('ascii')
    pubkey = payload[1 + name_len:1 + name_len + 160]

    client_id = uuid.uuid4().bytes
    client_id_hex = client_id.hex()

    STATE["clients"][client_id_hex] = {"name": name, "pubkey": pubkey}
    print(f"[REGISTER] Added {name} ({client_id_hex}), total {len(STATE['clients'])}")

    send_response(conn, RES_REGISTRATION_OK, client_id)

def handle_get_clients_list(conn, requester_hex):
    print(f"[CLIENTS LIST] STATE has {len(STATE['clients'])} clients")
    visible = [(cid_hex, info) for cid_hex, info in STATE["clients"].items()
               if cid_hex != requester_hex]

    payload = struct.pack("<H", len(visible))
    for cid_hex, info in visible:
        cid_bytes = bytes.fromhex(cid_hex)
        name_bytes = info["name"].encode('ascii')
        name_padded = name_bytes + b'\x00' * (255 - len(name_bytes))
        payload += cid_bytes + name_padded

    send_response(conn, RES_CLIENTS_LIST, payload)


# ===== 602 – Public Key =====
def handle_get_public_key(conn, payload: bytes):
    if len(payload) != 16:
        print("[PUBLIC KEY] Invalid UUID length.")
        send_response(conn, RES_ERROR, b"")
        return

    cid_hex = payload.hex()
    if cid_hex not in STATE["clients"]:
        print(f"[PUBLIC KEY] No such client: {cid_hex}")
        send_response(conn, RES_ERROR, b"")
        return

    pubkey = STATE["clients"][cid_hex]["pubkey"]
    send_response(conn, 2102, pubkey)
    print(f"[PUBLIC KEY] Sent key for {STATE['clients'][cid_hex]['name']}")


# ===== 603 – Send Message =====
def handle_send_message(conn, client_id: bytes, payload: bytes, state):
    if len(payload) < 21:
        print("[603] Invalid payload length.")
        send_response(conn, RES_ERROR, b"")
        return

    to_client_id = payload[0:16]
    msg_type = payload[16]
    content_size = struct.unpack("<I", payload[17:21])[0]
    content = payload[21:21 + content_size]

    print(f"[603] Message from {client_id.hex()} to {to_client_id.hex()}")
    print(f"     Type={msg_type}, ContentSize={content_size}")

    # Debug text output
    if msg_type == MSG_TYPE_TEXT:
        try:
            text = content.decode(errors="ignore")
            print(f"     Text message: {text}")
        except Exception:
            print("     (Failed to decode message content)")

    # Store pending message
    to_hex = to_client_id.hex()
    msg_record = (client_id.hex(), msg_type, content)
    state.setdefault("pending", {})
    state["pending"].setdefault(to_hex, []).append(msg_record)
    print(f"     Stored message for {to_hex}. Pending count: {len(state['pending'][to_hex])}")

    send_response(conn, RES_MESSAGE_RECEIVED, b"")


# ===== 604 – Get Waiting Messages =====
def handle_get_waiting_messages(conn, client_id: bytes, payload: bytes, state):
    hex_id = client_id.hex()
    pending = state.get("pending", {}).get(hex_id, [])
    print(f"[604] {len(pending)} waiting messages for {hex_id}")

    response = b''
    for from_id_hex, mtype, content in pending:
        part = bytes.fromhex(from_id_hex)
        part += struct.pack("<B", mtype)
        part += struct.pack("<I", len(content))
        part += content
        response += part

    # Clear delivered messages
    if hex_id in state.get("pending", {}):
        state["pending"][hex_id].clear()

    send_response(conn, 2104, response)
