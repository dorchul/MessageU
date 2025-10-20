import struct
import uuid
import time 
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
    MSG_ID_SIZE
)

VERBOSE = True
def log(msg):
    if VERBOSE:
        print(msg)

# ===== Global State =====
# Holds all connected clients and their pending messages in memory.
# This acts as an in-memory "database" for the MessageU server.
STATE = {
    # ------------------------------------------------------------
    # Registered clients table
    # ------------------------------------------------------------
    # Key:   client_id (hex string, 32 chars)
    # Value: {
    #     "name": str,         # Client's username (ASCII)
    #     "pubkey": bytes,     # Client's public RSA key (160B DER)
    #     "last_seen": float,  # Unix timestamp of last request
    # }
    "clients": {},

    # ------------------------------------------------------------
    # Pending messages (outbox/inbox)
    # ------------------------------------------------------------
    # Key:   recipient_id (hex string)
    # Value: list of dicts, each representing a pending message
    # Each message dict has:
    # {
    #     "from": str,     # Sender's client_id (hex string)
    #     "type": int,     # Message type (1=request key, 2=send key, 3=text, etc.)
    #     "content": bytes # Encrypted content bytes (may be empty for type 1)
    # }
    #
    # The message's "ID" in the protocol (for 2103/2104) is simply its
    # index in this list (0-based). We do NOT store 'id' inside each
    # message since it can always be derived by enumeration.
    "pending_messages": {},

    # ------------------------------------------------------------
    # (Optional) Global sequential counter
    # ------------------------------------------------------------
    # Currently unused, but kept for possible future extensions (e.g. logging,
    # or SQLite persistence where a global message index may be useful).
    # Can be ignored by current handlers (603/604 use list index instead).
    "msg_counter": 0
}

def send_response(conn, code, payload: bytes = b""):
    if code == RES_ERROR:
        payload = b""
    header = pack_response_header(code, len(payload))
    conn.sendall(header)
    if payload:
        conn.sendall(payload)
    log(f"[SEND_RESPONSE] Code={code}, PayloadSize={len(payload)} sent.")


def handle_register(conn, payload: bytes):
    if len(payload) != NAME_SIZE  + PUBKEY_SIZE:
        send_response(conn, RES_ERROR)
        return

    name_bytes = payload[:NAME_SIZE]
    name = name_bytes.split(b'\x00', 1)[0].decode('ascii', errors='ignore')

    # reject non-printable ASCII
    if not all(32 <= b < 127 for b in name.encode('ascii', 'ignore')):
        send_response(conn, RES_ERROR)
        return

    # reject duplicate name
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


def handle_get_clients_list(conn, requester_hex):
    log(f"[CLIENTS LIST] STATE has {len(STATE['clients'])} clients")
    visible = [
        (cid_hex, info)
        for cid_hex, info in STATE["clients"].items()
        if cid_hex != requester_hex
    ]

    payload = b''
    for cid_hex, info in visible:
        cid_bytes = bytes.fromhex(cid_hex)
        name_bytes = info["name"].encode('ascii')
        name_padded = name_bytes + b'\x00' * (NAME_SIZE - len(name_bytes))
        payload += cid_bytes + name_padded

    send_response(conn, RES_CLIENTS_LIST, payload)



# ===== 602 – Public Key =====
def handle_get_public_key(conn, payload: bytes):
    if len(payload) != UUID_SIZE:
        log("[PUBLIC KEY] Invalid UUID length.")
        send_response(conn, RES_ERROR)
        return

    cid_hex = payload.hex()
    if cid_hex not in STATE["clients"]:
        log(f"[PUBLIC KEY] No such client: {cid_hex}")
        send_response(conn, RES_ERROR)
        return

    pubkey = STATE["clients"][cid_hex]["pubkey"]

    # Build payload: [ClientID(16B)] + [PublicKey(160B)]
    cid_bytes = bytes.fromhex(cid_hex)
    payload_out = cid_bytes + pubkey

    send_response(conn, RES_PUBLIC_KEY, payload_out)
    log(f"[PUBLIC KEY] Sent key for {STATE['clients'][cid_hex]['name']}")


# ===== 603 – Send Message =====
def handle_send_message(conn, payload: bytes, header):
    try:
        # --- Basic length validation ---
        min_size = UUID_SIZE + MSG_TYPE_SIZE + CONTENT_SIZE
        if len(payload) < min_size:
            log("[SEND MESSAGE] Payload too short.")
            send_response(conn, RES_ERROR)
            return

        # --- Parse payload fields ---
        to_uuid = payload[0: UUID_SIZE].hex()
        msg_type = payload[UUID_SIZE]
        content_size = int.from_bytes(payload[UUID_SIZE + MSG_TYPE_SIZE : UUID_SIZE + MSG_TYPE_SIZE + CONTENT_SIZE], "little")
        content = payload[min_size:]

        if len(content) != content_size:
            log(f"[SEND MESSAGE] Invalid payload size. Declared={content_size}, actual={len(content)})")
            send_response(conn, RES_ERROR)
            return

        from_uuid = header["client_id"]

        # --- Validate destination ---
        if to_uuid not in STATE["clients"]:
            log(f"[SEND MESSAGE] Destination {to_uuid} not found.")
            send_response(conn, RES_ERROR)
            return

        # --- Create recipient queue if needed ---
        STATE["pending_messages"].setdefault(to_uuid, [])

        # --- Compute message ID (index in list) ---
        message_id = len(STATE["pending_messages"][to_uuid])

        # --- Store message (dict-based) ---
        STATE["pending_messages"][to_uuid].append({
            "from": from_uuid,
            "type": msg_type,
            "content": content
        })

        log(f"[SEND MESSAGE] Stored msg#{message_id} from {from_uuid[:8]} → {to_uuid[:8]} "
            f"(type={msg_type}, size={len(content)})")

        # --- Build response (2103) ---
        # Payload = toClientID(16B) | messageID(4B LE)
        response_payload = bytes.fromhex(to_uuid) + message_id.to_bytes(4, "little")
        send_response(conn, RES_MESSAGE_RECEIVED, response_payload)

    except Exception as e:
        log(f"[SEND MESSAGE] Exception: {e}")
        send_response(conn, RES_ERROR)

# ===== 604 – Get Waiting Messages =====
def handle_get_waiting_messages(conn, payload: bytes, header):
    try:
        to_uuid = header["client_id"]

        # Verify this client exists
        if to_uuid not in STATE["clients"]:
            log(f"[GET WAITING] Unknown client {to_uuid}")
            send_response(conn, RES_ERROR, b"")
            return

        # No messages waiting
        if to_uuid not in STATE["pending_messages"] or not STATE["pending_messages"][to_uuid]:
            log(f"[GET WAITING] No pending messages for {to_uuid[:8]}")
            send_response(conn, RES_WAITING_MESSAGES, b"")  # empty payload allowed
            return

        messages = STATE["pending_messages"][to_uuid]
        payload_bytes = bytearray()

        for msg_id, msg in enumerate(messages):
            from_uuid = msg["from"]
            msg_type  = msg["type"]
            content   = msg["content"]
            msg_size  = len(content)
            payload_bytes += bytes.fromhex(from_uuid)
            payload_bytes += msg_id.to_bytes(MSG_ID_SIZE, "little")
            payload_bytes += msg_type.to_bytes(MSG_TYPE_SIZE, "little")
            payload_bytes += msg_size.to_bytes(CONTENT_SIZE, "little")
            payload_bytes += content

            log(f"[GET WAITING] → msg#{msg_id} from {from_uuid[:8]} "
                  f"(type={msg_type}, size={msg_size})")

        # Clear the list after sending
        STATE["pending_messages"][to_uuid] = []

        # Send combined payload
        send_response(conn, RES_WAITING_MESSAGES, bytes(payload_bytes))
        log(f"[GET WAITING] Sent {len(messages)} messages to {to_uuid[:8]}")

    except Exception as e:
        log(f"[GET WAITING] Exception: {e}")
        send_response(conn, RES_ERROR, b"")

