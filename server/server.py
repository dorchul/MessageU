import socket
import struct

VERSION = 1
REQ_HEADER_FORMAT = "<16sBHI"  # Little Endian: ClientID(16B), Version(1B), Code(2B), PayloadSize(4B)
REQ_HEADER_SIZE = struct.calcsize(REQ_HEADER_FORMAT)


def read_port():
    """Read port number from myport.info"""
    with open("myport.info", "r") as f:
        return int(f.readline().strip())


def handle_client(conn, addr):
    print(f"[+] Connected: {addr}")
    data = conn.recv(REQ_HEADER_SIZE)
    if len(data) < REQ_HEADER_SIZE:
        print("[-] Incomplete header")
        conn.close()
        return

    client_id, version, code, payload_size = struct.unpack(REQ_HEADER_FORMAT, data)
    print(f"[HEADER] Version={version}, Code={code}, PayloadSize={payload_size}")

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
