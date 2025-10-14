import uuid
import struct
import time
from collections import namedtuple
from protocol import (
    VERSION,
    RES_PUBLIC_KEY,
    RES_REGISTRATION_OK,
    RES_CLIENTS_LIST,
    RES_ERROR,
    PUBKEY_SIZE,
    RES_HEADER_FORMAT,
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
