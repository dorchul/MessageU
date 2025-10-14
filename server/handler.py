import uuid
import struct
import time
from collections import namedtuple
from protocol import (
    VERSION,
    REQ_REGISTER,
    REQ_CLIENTS_LIST, 
    RES_REGISTRATION_OK,
    RES_CLIENTS_LIST,
    RES_ERROR,
    PUBKEY_SIZE,
    RES_HEADER_FORMAT,
)


Client = namedtuple('Client', 'id name pubkey last_seen')

STATE = {
    'clients_by_id': {},
    'clients_by_name': {},
}


def send_response(conn, code, payload=b''):
    """Send a binary response header + payload."""
    hdr = struct.pack(RES_HEADER_FORMAT, VERSION, code, len(payload))
    conn.sendall(hdr + payload)


def handle_register(conn, payload: bytes):
    """Handle REGISTER (600) request."""
    # Each register payload is: NameLen(1) | Name | PublicKey(160)
    if len(payload) < 1 + PUBKEY_SIZE:
        return send_response(conn, RES_ERROR, b'bad payload')

    name_len = payload[0]
    if len(payload) != 1 + name_len + PUBKEY_SIZE:
        return send_response(conn, RES_ERROR, b'bad length')

    name = payload[1:1 + name_len].decode('utf-8', 'replace')
    pubkey = payload[1 + name_len:]

    # Check if user already exists (idempotent registration)
    if name in STATE['clients_by_name']:
        cid = STATE['clients_by_name'][name]
    else:
        cid = uuid.uuid4().bytes
        STATE['clients_by_name'][name] = cid
        STATE['clients_by_id'][cid] = Client(cid, name, pubkey, time.time())

    print(f"[REGISTER] {name} -> {cid.hex()}")
    send_response(conn, RES_REGISTRATION_OK, cid)

def handle_get_clients_list(conn):
    clients = list(STATE['clients_by_id'].values())
    payload = struct.pack('<H', len(clients))
    for c in clients:
        name_bytes = c.name.encode('utf-8')
        payload += c.id + struct.pack('<B', len(name_bytes)) + name_bytes

    print(f"[CLIENTS LIST] Returning {len(clients)} clients")
    send_response(conn, RES_CLIENTS_LIST, payload)
