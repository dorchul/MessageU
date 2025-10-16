import socket
import struct
from protocol import (
    REQ_HEADER_FORMAT,
    REQ_REGISTER,
    REQ_CLIENTS_LIST,
    REQ_PUBLIC_KEY,
    REQ_SEND_MESSAGE,
    REQ_WAITING_MESSAGES,
    RES_ERROR
)
from handler import (
    handle_register,
    handle_get_clients_list,
    handle_get_public_key,
    handle_send_message, 
    send_response,
    handle_get_waiting_messages,
    STATE
)

VERSION = 1
REQ_HEADER_SIZE = struct.calcsize(REQ_HEADER_FORMAT)

def read_port():
    """Read port number from myport.info"""
    with open("myport.info", "r") as f:
        return int(f.readline().strip())

def recv_exact(conn, size):
    """Receive exactly `size` bytes."""
    buf = b''
    while len(buf) < size:
        chunk = conn.recv(size - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def handle_client(conn, addr):
    print(f"[+] Connected: {addr}")
    try:
        while True:
            data = recv_exact(conn, REQ_HEADER_SIZE)
            if not data:
                break

            client_id_bytes, version, code, payload_size = struct.unpack(REQ_HEADER_FORMAT, data)
            client_id_hex = client_id_bytes.hex()
            payload = recv_exact(conn, payload_size) if payload_size > 0 else b''

            if code == REQ_REGISTER:
                handle_register(conn, payload)
            elif code == REQ_CLIENTS_LIST:
                handle_get_clients_list(conn, client_id_hex)
            elif code == REQ_PUBLIC_KEY:
                handle_get_public_key(conn, payload)
            elif code == REQ_SEND_MESSAGE:
                handle_send_message(conn, client_id_bytes, payload)
            elif code == REQ_WAITING_MESSAGES:
                handle_get_waiting_messages(conn, client_id_bytes, payload)
            else:
                send_response(conn, RES_ERROR, b'unknown code')

    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        conn.close()
        print(f"[-] Disconnected: {addr}")


import threading

def main():
    port = read_port()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", port))
        s.listen(5)
        print(f"[SERVER] Listening on port {port}")
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()

if __name__ == "__main__":
    main()
