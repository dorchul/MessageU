import struct

# ===== Protocol Constants =====
VERSION = 1
CLIENT_ID_SIZE = 16
PUBKEY_SIZE = 160


# Request Codes
REQ_REGISTER = 600
REQ_CLIENTS_LIST = 601
REQ_PUBLIC_KEY = 602
REQ_SEND_MESSAGE = 603
REQ_WAITING_MESSAGES = 604

# Response Codes
RES_REGISTRATION_OK = 2100
RES_CLIENTS_LIST = 2101
RES_PUBLIC_KEY = 2102
RES_MESSAGE_RECEIVED = 2103
RES_WAITING_MESSAGES = 2104
RES_ERROR = 9000

# ===== Header Formats =====
# Little endian: < means little-endian
REQ_HEADER_FORMAT = "<16sBHI"   # ClientID(16B) | Version(1B) | Code(2B) | PayloadSize(4B)
RES_HEADER_FORMAT = "<BHI"      # Version(1B) | Code(2B) | PayloadSize(4B)

REQ_HEADER_SIZE = struct.calcsize(REQ_HEADER_FORMAT)
RES_HEADER_SIZE = struct.calcsize(RES_HEADER_FORMAT)

# ===== Helpers =====
def pack_request_header(client_id: bytes, code: int, payload_size: int) -> bytes:
    return struct.pack(REQ_HEADER_FORMAT, client_id, VERSION, code, payload_size)

def unpack_request_header(data: bytes):
    client_id, version, code, payload_size = struct.unpack(REQ_HEADER_FORMAT, data)
    return {
        "client_id": client_id,
        "version": version,
        "code": code,
        "payload_size": payload_size
    }

def pack_response_header(code: int, payload_size: int) -> bytes:
    return struct.pack(RES_HEADER_FORMAT, VERSION, code, payload_size)

def unpack_response_header(data: bytes):
    version, code, payload_size = struct.unpack(RES_HEADER_FORMAT, data)
    return {
        "version": version,
        "code": code,
        "payload_size": payload_size
    }