# ===============================
# models.py – Data Models for MessageU Server
# ===============================
import time
from protocol import (
    NAME_SIZE,
    PUBKEY_SIZE,
    UUID_SIZE,
    MSG_ID_SIZE,
    MSG_TYPE_SIZE,
    CONTENT_SIZE,
)

# ===============================
# Client Model
# ===============================
class Client:
    def __init__(self, id_bytes: bytes, username: str, pubkey: bytes, last_seen: float = None):
        if not isinstance(id_bytes, (bytes, bytearray)) or len(id_bytes) != UUID_SIZE:
            raise ValueError("Invalid client ID (must be 16 bytes)")
        if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != PUBKEY_SIZE:
            raise ValueError("Invalid public key size")
        self.id = id_bytes
        self.username = username
        self.pubkey = pubkey
        self.last_seen = last_seen or time.time()

    # === Serialization for DB ===
    def to_row(self):
        """Convert to tuple for SQLite insertion."""
        return (self.id, self.username, self.pubkey, self.last_seen)

    @classmethod
    def from_row(cls, row):
        """Create Client from SQLite row tuple."""
        id_bytes, username, pubkey, last_seen = row
        return cls(id_bytes, username, pubkey, last_seen)

    # === Serialization for Protocol ===
    def to_payload_entry(self):
        """Serialize client info to bytes for RES_CLIENTS_LIST."""
        name_bytes = self.username.encode("ascii", errors="ignore")
        name_padded = name_bytes + b"\x00" * (NAME_SIZE - len(name_bytes))
        return self.id + name_padded


# ===============================
# Message Model
# ===============================
class Message:
    def __init__(self, msg_id: int, to_id: bytes, from_id: bytes, msg_type: int, content: bytes):
        if not isinstance(to_id, (bytes, bytearray)) or len(to_id) != UUID_SIZE:
            raise ValueError("Invalid ToClient UUID (must be 16 bytes)")
        if not isinstance(from_id, (bytes, bytearray)) or len(from_id) != UUID_SIZE:
            raise ValueError("Invalid FromClient UUID (must be 16 bytes)")
        if not (0 <= msg_type <= 255):
            raise ValueError("Invalid message type")
        self.id = msg_id
        self.to_id = to_id
        self.from_id = from_id
        self.msg_type = msg_type
        self.content = content or b""

    # === Serialization for DB ===
    def to_row(self):
        """Convert to tuple for SQLite insertion."""
        return (self.to_id, self.from_id, self.msg_type, self.content)

    @classmethod
    def from_row(cls, row):
        """Create Message from SQLite row tuple."""
        msg_id, to_id, from_id, msg_type, content = row
        return cls(msg_id, to_id, from_id, msg_type, content)

    # === Serialization for Protocol ===
    def to_payload_entry(self):
        """Serialize to bytes for RES_WAITING_MESSAGES payload."""
        msg_size = len(self.content)
        return (
            self.from_id
            + self.id.to_bytes(MSG_ID_SIZE, "little")
            + self.msg_type.to_bytes(MSG_TYPE_SIZE, "little")
            + msg_size.to_bytes(CONTENT_SIZE, "little")
            + self.content
        )
