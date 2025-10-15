import uuid
import struct
import time
from collections import namedtuple
from protocol import (
    VERSION,
    RES_PUBLIC_KEY,
    RES_REGISTRATION_OK,
    RES_CLIENTS_LIST,
    RES_MESSAGE_RECEIVED,
    RES_ERROR,
    PUBKEY_SIZE,
    RES_HEADER_FORMAT,
    MSG_TYPE_FILE,
    MSG_TYPE_SEND_SYM,
    MSG_TYPE_TEXT,
    MSG_TYPE_REQUEST_SYM
)

Client = namedtuple('Client', 'id name pubkey last_seen')

STATE = {
    'clients_by_id': {},    # { uuid_bytes: Client(...) }
    'clients_by_name': {},  # { name: uuid_bytes }
}

# ===== Response Helper =====
def send_response(conn, code, payload=b''):
    """Send a binary response header + payload."""
    hdr = struct.pack(RES_HEADER_FORMAT, VERSION, code, len(payload))
    conn.sendall(hdr + payload)

# ===== 600 REGISTER =====
def handle_register(conn, payload: bytes):
    """Handle REGISTER (600) request."""
    if len(payload) < 1 + PUBKEY_SIZE:
        return send_response(conn, RES_ERROR, b'bad payload')

    name_len = payload[0]
    if len(payload) != 1 + name_len + PUBKEY_SIZE:
        return send_response(conn, RES_ERROR, b'bad length')

    name = payload[1:1 + name_len].decode('utf-8', 'replace')
    pubkey = payload[1 + name_len:]

    # Check if user already exists (idempotent)
    if name in STATE['clients_by_name']:
        cid = STATE['clients_by_name'][name]
    else:
        cid = uuid.uuid4().bytes
        STATE['clients_by_name'][name] = cid
        STATE['clients_by_id'][cid] = Client(cid, name, pubkey, time.time())

    print(f"[REGISTER] {name} -> {cid.hex()}")
    send_response(conn, RES_REGISTRATION_OK, cid)

# ===== 601 CLIENTS LIST =====
def handle_get_clients_list(conn):
    clients = list(STATE['clients_by_id'].values())
    payload = struct.pack('<H', len(clients))
    for c in clients:
        name_bytes = c.name.encode('utf-8')
        payload += c.id + struct.pack('<B', len(name_bytes)) + name_bytes

    print(f"[CLIENTS LIST] Returning {len(clients)} clients")
    send_response(conn, RES_CLIENTS_LIST, payload)

# ===== 602 PUBLIC KEY =====
def handle_get_public_key(conn, payload):
    """Handle 602: return public key for given client UUID."""
    if len(payload) != 16:
        print("[PUBLIC KEY] Invalid payload size")
        return send_response(conn, RES_ERROR, b'')

    target_id = payload
    client = STATE['clients_by_id'].get(target_id)

    if not client:
        print("[PUBLIC KEY] UUID not found")
        return send_response(conn, RES_ERROR, b'')

    send_response(conn, RES_PUBLIC_KEY, client.pubkey)
    print(f"[PUBLIC KEY] Sent key for {client.name}")

def handle_send_message(conn, client_id, payload, state):
    """
    Handle incoming message (603).
    Payload structure:
        ToClientID(16B) | Type(1B) | ContentSize(4B) | Content(variable)
    """
    # --- Parse payload header ---
    if len(payload) < 21:  # 16 + 1 + 4
        print("Invalid payload length for 603")
        send_response(conn, RES_MESSAGE_RECEIVED, b"")
        return

    to_client_id = payload[0:16]
    msg_type = payload[16]
    content_size = struct.unpack("<I", payload[17:21])[0]
    content = payload[21 : 21 + content_size]

    print(f"[603] Message from {client_id.hex()} to {to_client_id.hex()}")
    print(f"       Type={msg_type}, ContentSize={content_size}")

    # --- Optional debug output ---
    if msg_type == MSG_TYPE_TEXT:
        try:
            text = content.decode(errors="ignore")
            print(f"       Text message: {text}")
        except Exception:
            print("       (Failed to decode message content)")

    elif msg_type == MSG_TYPE_REQUEST_SYM:
        print("       Request for symmetric key")

    elif msg_type == MSG_TYPE_SEND_SYM:
        print("       Received symmetric key (RSA encrypted)")

    elif msg_type == MSG_TYPE_FILE:
        print("       File transfer (ignored for now)")

    # Store or forward logic can go here later (bonus/extension)
    # For now, just acknowledge message receipt.

    send_response(conn, RES_MESSAGE_RECEIVED, b"")
