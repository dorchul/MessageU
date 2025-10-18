import struct
import uuid

from protocol import pack_response_header

from protocol import (
    RES_ERROR,
    RES_CLIENTS_LIST,
    RES_PUBLIC_KEY,
    RES_MESSAGE_RECEIVED,
    RES_WAITING_MESSAGES,
    RES_REGISTRATION_OK,
)

VERBOSE = True
def log(msg):
    if VERBOSE:
        print(msg)

# ===== Global State =====
# Holds clients and their pending messages
STATE = {
    "clients": {},   # client_id(hex) → {"name": str, "pubkey": bytes}
    "pending": {}    # to_client_id(hex) → [ (from_id_hex, type, content_bytes) ]
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
    if len(payload) != 255 + 160:
        send_response(conn, RES_ERROR)   # no payload
        return

    name_bytes = payload[:255]
    name = name_bytes.split(b'\x00', 1)[0].decode('ascii', errors='ignore')
    pubkey = payload[255:415]

    client_id = uuid.uuid4().bytes
    client_id_hex = client_id.hex()
    STATE["clients"][client_id_hex] = {"name": name, "pubkey": pubkey}

    send_response(conn, RES_REGISTRATION_OK, client_id)  # exactly 16B

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
        name_padded = name_bytes + b'\x00' * (255 - len(name_bytes))
        payload += cid_bytes + name_padded

    send_response(conn, RES_CLIENTS_LIST, payload)



# ===== 602 – Public Key =====
def handle_get_public_key(conn, payload: bytes):
    if len(payload) != 16:
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
        if len(payload) < 21:
            log("[SEND MESSAGE] Payload too short.")
            send_response(conn, RES_ERROR, b"")
            return

        to_uuid = payload[0:16].hex()
        msg_type = payload[16] # msg_type: 1=RequestSym, 2=SendSym, 3=Text
        content_size = int.from_bytes(payload[17:21], "little")
        if len(payload) != 21 + content_size:
            log(f"[SEND MESSAGE] Invalid payload size. Declared={content_size}, actual={len(payload)-21}")
            send_response(conn, RES_ERROR, b"")
            return

        content = payload[21:]
        from_uuid = header["client_id"]

        if to_uuid not in STATE["clients"]:
            log(f"[SEND MESSAGE] Destination {to_uuid} not found.")
            send_response(conn, RES_ERROR, b"")
            return

        if to_uuid not in STATE["pending"]:
            STATE["pending"][to_uuid] = []

        # assign id = 1 + current count for that recipient
        message_id = len(STATE["pending"][to_uuid]) + 1

        # --- Store message ---
        content_size = len(content)
        STATE["pending"][to_uuid].append((from_uuid, message_id, msg_type, content_size, content))


        log(f"[SEND MESSAGE] Stored msg#{message_id} from {from_uuid[:8]} → {to_uuid[:8]} "
              f"(type={msg_type}, size={content_size})")

        # 2103 payload = toClientID(16) | messageID(4, LE)
        response_payload = bytes.fromhex(to_uuid) + message_id.to_bytes(4, "little")
        send_response(conn, RES_MESSAGE_RECEIVED, response_payload)

    except Exception as e:
        log(f"[SEND MESSAGE] Exception: {e}")
        send_response(conn, RES_ERROR, b"")



# ===== 604 – Get Waiting Messages =====
def handle_get_waiting_messages(conn, payload: bytes, header):
    try:
        client_uuid = header["client_id"]

        # Verify this client exists
        if client_uuid not in STATE["clients"]:
            log(f"[GET WAITING] Unknown client {client_uuid}")
            send_response(conn, RES_ERROR, b"")
            return

        # No messages waiting
        if client_uuid not in STATE["pending"] or not STATE["pending"][client_uuid]:
            log(f"[GET WAITING] No pending messages for {client_uuid[:8]}")
            send_response(conn, RES_WAITING_MESSAGES, b"")  # empty payload allowed
            return

        messages = STATE["pending"][client_uuid]
        payload_bytes = bytearray()

        for (from_uuid, msg_id, msg_type, msg_size, content) in messages:
            payload_bytes += bytes.fromhex(from_uuid)
            payload_bytes += msg_id.to_bytes(4, "little")
            payload_bytes += msg_type.to_bytes(1, "little")
            payload_bytes += msg_size.to_bytes(4, "little")
            payload_bytes += content

            log(f"[GET WAITING] → msg#{msg_id} from {from_uuid[:8]} "
                  f"(type={msg_type}, size={msg_size})")

        # Clear the list after sending
        STATE["pending"][client_uuid] = []

        # Send combined payload
        send_response(conn, RES_WAITING_MESSAGES, bytes(payload_bytes))
        log(f"[GET WAITING] Sent {len(messages)} messages to {client_uuid[:8]}")

    except Exception as e:
        log(f"[GET WAITING] Exception: {e}")
        send_response(conn, RES_ERROR, b"")

