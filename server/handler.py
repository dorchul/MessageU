import struct
import uuid
import time
import threading
import os
import uuid

from db import (
    add_client, 
    list_clients, 
    client_exists, 
    update_last_seen, 
    get_client_by_id, 
    add_message, 
    get_messages_for_client, 
    delete_messages_for_client
)
from models import Client, Message

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


def handle_register(conn, payload: bytes):
    try:
        if len(payload) != NAME_SIZE + PUBKEY_SIZE:
            send_response(conn, RES_ERROR)
            return

        name_bytes = payload[:NAME_SIZE]
        name = name_bytes.split(b'\x00', 1)[0].decode('ascii', errors='ignore')

        # basic validation (printable ASCII)
        if not name or not all(32 <= b < 127 for b in name.encode('ascii', 'ignore')):
            send_response(conn, RES_ERROR)
            return

        pubkey = payload[NAME_SIZE:NAME_SIZE + PUBKEY_SIZE]

        # create a new UUID and client
        client_id = uuid.uuid4().bytes
        client = Client(client_id, name, pubkey)

        # attempt to insert into DB
        ok = add_client(client)
        if not ok:
            send_response(conn, RES_ERROR)
            return

        send_response(conn, RES_REGISTRATION_OK, client_id)
        print(f"[REGISTER] {name} registered ({client_id.hex()[:8]}) [DB persisted]")

    except Exception as e:
        print(f"[REGISTER] Exception: {e}")
        send_response(conn, RES_ERROR)



# ===== 601 – Get Client List =====
def handle_get_clients_list(conn, requester_hex):
    try:
        requester_bytes = bytes.fromhex(requester_hex)

        # verify requester exists
        if not get_client_by_id(requester_bytes):
            send_response(conn, RES_ERROR)
            return

        update_last_seen(requester_bytes)

        # fetch all other clients
        others = list_clients(exclude_id=requester_bytes)

        # build payload
        payload = b"".join(c.to_payload_entry() for c in others)

        send_response(conn, RES_CLIENTS_LIST, payload)
        log(f"[CLIENTS LIST] Sent {len(others)} entries (from DB).")

    except Exception as e:
        log(f"[CLIENTS LIST] Exception: {e}")
        send_response(conn, RES_ERROR)



# ===== 602 – Public Key =====
def handle_get_public_key(conn, payload: bytes, requester_hex):
    try:
        if len(payload) != UUID_SIZE:
            send_response(conn, RES_ERROR)
            return

        target_id = payload  # raw 16-byte UUID
        requester_id = bytes.fromhex(requester_hex)

        # verify target exists
        target = get_client_by_id(target_id)
        if not target:
            send_response(conn, RES_ERROR)
            return

        # update requester last_seen
        update_last_seen(requester_id)

        # build payload: ID(16) + PublicKey(160)
        payload_out = target.id + target.pubkey

        send_response(conn, RES_PUBLIC_KEY, payload_out)
        log(f"[PUBLIC KEY] Sent key for {target.username}")

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

        to_uuid = payload[0:UUID_SIZE]         
        msg_type = payload[UUID_SIZE]                      
        content_size = int.from_bytes(
            payload[UUID_SIZE + MSG_TYPE_SIZE : UUID_SIZE + MSG_TYPE_SIZE + CONTENT_SIZE],
            "little"
        )                                              
        content = payload[min_size:]

        if len(content) != content_size or content_size > MAX_PAYLOAD_SIZE:
            send_response(conn, RES_ERROR)
            return

        from_uuid = bytes.fromhex(header["client_id"])    

        # --- Verify recipient exists ---
        if not client_exists(to_uuid):                        
            send_response(conn, RES_ERROR)
            return

        # --- Create message model and store in DB ---
        msg = Message(None, to_uuid, from_uuid, msg_type, content) 
        msg_id = add_message(msg)                                

        # --- Update sender's last_seen ---
        update_last_seen(from_uuid)                   

        # --- Build response payload: ToClient(16) + MsgID(4B LE) ---
        response_payload = to_uuid + msg_id.to_bytes(4, "little")  
        send_response(conn, RES_MESSAGE_RECEIVED, response_payload) 

        log(f"[SEND MESSAGE] #{msg_id} {header['client_id'][:8]} → {to_uuid.hex()[:8]} stored in DB") 

    except Exception as e:
        log(f"[SEND MESSAGE] Exception: {e}")
        send_response(conn, RES_ERROR)
        
# ===== 604 – Get Waiting Messages =====
def handle_get_waiting_messages(conn, payload: bytes, header):
    try:
        to_uuid_hex = header["client_id"]
        to_uuid = bytes.fromhex(to_uuid_hex)

        # verify client exists
        if not get_client_by_id(to_uuid):
            send_response(conn, RES_ERROR)
            return

        # fetch all messages for this client
        messages = get_messages_for_client(to_uuid)

        # update last_seen for the client
        update_last_seen(to_uuid)

        if not messages:
            send_response(conn, RES_WAITING_MESSAGES, b"")
            log(f"[GET WAITING] No pending messages for {to_uuid_hex[:8]}")
            return

        # build payload
        payload_bytes = bytearray()
        for msg in messages:
            payload_bytes += msg.to_payload_entry()

        # clear messages after successful retrieval
        delete_messages_for_client(to_uuid)

        send_response(conn, RES_WAITING_MESSAGES, bytes(payload_bytes))
        log(f"[GET WAITING] Delivered and deleted {len(messages)} messages for {to_uuid_hex[:8]}")

    except Exception as e:
        log(f"[GET WAITING] Exception: {e}")
        send_response(conn, RES_ERROR)
