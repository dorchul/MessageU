import socket
import struct
from protocol import REQ_HEADER_FORMAT, REQ_REGISTER
from handler import handle_register

VERSION = 1
REQ_HEADER_SIZE = struct.calcsize(REQ_HEADER_FORMAT)


def read_port():
    """Read port number from myport.info"""
    with open("myport.info", "r") as f:
        return int(f.readline().strip())


def recv_exact(conn, size):
    """Receive exactly `size` bytes"""
    buf = b''
    while len(buf) < size:
        chunk = conn.recv(size - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def handle_client(conn, addr):
    print(f"[+] Connected: {addr}")
    data = recv_exact(conn, REQ_HEADER_SIZE)
    if not data:
        print("[-] Incomplete header")
        conn.close()
        return

    client_id, version, code, payload_size = struct.unpack(REQ_HEADER_FORMAT, data)
    print(f"[HEADER] Version={version}, Code={code}, PayloadSize={payload_size}")

    payload = recv_exact(conn, payload_size) if payload_size > 0 else b''

    if code == REQ_REGISTER:
        handle_register(conn, payload)
    else:
        print(f"[-] Unknown request code: {code}")

    conn.close()


def main():
    port = read_port()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", port))
        s.listen(5)
        print(f"[SERVER] Listening on port {port}")

        while True:
            conn, addr = s.accept()
            handle_client(conn, addr)


if __name__ == "__main__":
    main()
