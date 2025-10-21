import socket
import struct
import threading
from protocol import (
    REQ_HEADER_FORMAT,
    REQ_REGISTER,
    REQ_CLIENTS_LIST,
    REQ_PUBLIC_KEY,
    REQ_SEND_MESSAGE,
    REQ_WAITING_MESSAGES,
    RES_ERROR,
)
from handler import (
    handle_register,
    handle_get_clients_list,
    handle_get_public_key,
    handle_send_message,
    handle_get_waiting_messages,
    send_response,
)

# ==============================
# Configuration
# ==============================
VERBOSE = True
def log(msg):
    if VERBOSE:
        print(msg)

VERSION = 1
REQ_HEADER_SIZE = struct.calcsize(REQ_HEADER_FORMAT)

ROUTES = {
    REQ_REGISTER: handle_register,
    REQ_CLIENTS_LIST: handle_get_clients_list,
    REQ_PUBLIC_KEY: handle_get_public_key,
    REQ_SEND_MESSAGE: handle_send_message,
    REQ_WAITING_MESSAGES: handle_get_waiting_messages,
}

# ==============================
# Utilities
# ==============================
def read_port():
    """Read port number from myport.info"""
    with open("myport.info", "r") as f:
        return int(f.readline().strip())

def recv_exact(conn, size):
    """Receive exactly `size` bytes or None if connection closed."""
    buf = b""
    while len(buf) < size:
        chunk = conn.recv(size - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

# ==============================
# Client connection handler
# ==============================
def handle_client(conn, addr):
    log(f"[+] Connected: {addr}")
    try:
        # Read request header
        data = recv_exact(conn, REQ_HEADER_SIZE)
        if not data:
            return

        client_id_bytes, version, code, payload_size = struct.unpack(REQ_HEADER_FORMAT, data)
        client_id_hex = client_id_bytes.hex()
        payload = recv_exact(conn, payload_size) if payload_size > 0 else b""

        log(f"[REQ] Code={code}, From={client_id_hex[:8]}, Payload={payload_size}B")

        # Build header info dict (used by 603/604)
        header = {
            "client_id": client_id_hex,
            "version": version,
            "code": code,
        }

        # Route to appropriate handler
        handler = ROUTES.get(code)
        if handler:
            if code in (REQ_REGISTER, REQ_PUBLIC_KEY):
                handler(conn, payload)
            elif code == REQ_CLIENTS_LIST:
                handler(conn, client_id_hex)
            else:
                handler(conn, payload, header)
        else:
            send_response(conn, RES_ERROR)

    except Exception as e:
        log(f"[ERROR] {e}")
    finally:
        conn.close()
        log(f"[-] Disconnected: {addr}")

# ==============================
# Main server loop
# ==============================
def main():
    port = read_port()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", port))   
        s.listen(5)
        log(f"[SERVER] Listening on port {port}")

        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()

# ==============================
# Entry point
# ==============================
if __name__ == "__main__":
    main()
