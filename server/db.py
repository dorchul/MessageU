# ===============================
# db.py – SQLite persistence layer for MessageU Server
# ===============================
import sqlite3
import threading
import time
from models import Client, Message

DB_PATH = "defensive.db"
DB_LOCK = threading.RLock()

# ===============================
# Initialization
# ===============================
def _init_db():
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        cur = conn.cursor()

        # === clients table ===
        cur.execute("""
            CREATE TABLE IF NOT EXISTS clients (
                ID BLOB(16) PRIMARY KEY,
                UserName TEXT UNIQUE NOT NULL,
                PublicKey BLOB(160) NOT NULL,
                LastSeen REAL NOT NULL
            )
        """)

        # === messages table ===
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                ToClient BLOB(16) NOT NULL,
                FromClient BLOB(16) NOT NULL,
                Type INTEGER NOT NULL,
                Content BLOB NOT NULL
            )
        """)

        conn.commit()
        conn.close()

# Initialize once when imported
_init_db()


# ===============================
# Utility
# ===============================
def _connect():
    """Get a new SQLite connection (thread-safe)."""
    return sqlite3.connect(DB_PATH, check_same_thread=False)


# ===============================
# Clients
# ===============================
def add_client(client: Client) -> bool:
    """Insert a new client. Returns True on success, False if username exists."""
    with DB_LOCK:
        conn = _connect()
        try:
            conn.execute(
                "INSERT INTO clients (ID, UserName, PublicKey, LastSeen) VALUES (?, ?, ?, ?)",
                client.to_row(),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()


def get_client_by_id(client_id: bytes) -> Client | None:
    with DB_LOCK:
        conn = _connect()
        cur = conn.cursor()
        cur.execute("SELECT ID, UserName, PublicKey, LastSeen FROM clients WHERE ID = ?", (client_id,))
        row = cur.fetchone()
        conn.close()
        return Client.from_row(row) if row else None


def get_client_by_name(username: str) -> Client | None:
    with DB_LOCK:
        conn = _connect()
        cur = conn.cursor()
        cur.execute("SELECT ID, UserName, PublicKey, LastSeen FROM clients WHERE UserName = ?", (username,))
        row = cur.fetchone()
        conn.close()
        return Client.from_row(row) if row else None


def list_clients(exclude_id: bytes | None = None) -> list[Client]:
    with DB_LOCK:
        conn = _connect()
        cur = conn.cursor()
        if exclude_id:
            cur.execute("SELECT ID, UserName, PublicKey, LastSeen FROM clients WHERE ID != ?", (exclude_id,))
        else:
            cur.execute("SELECT ID, UserName, PublicKey, LastSeen FROM clients")
        rows = cur.fetchall()
        conn.close()
        return [Client.from_row(r) for r in rows]


def update_last_seen(client_id: bytes):
    with DB_LOCK:
        conn = _connect()
        conn.execute("UPDATE clients SET LastSeen=? WHERE ID=?", (time.time(), client_id))
        conn.commit()
        conn.close()


def client_exists(client_id: bytes) -> bool:
    with DB_LOCK:
        conn = _connect()
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM clients WHERE ID=?", (client_id,))
        exists = cur.fetchone() is not None
        conn.close()
        return exists


# ===============================
# Messages
# ===============================
def add_message(msg: Message) -> int:
    """Insert a new message and return its auto-increment ID."""
    with DB_LOCK:
        conn = _connect()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO messages (ToClient, FromClient, Type, Content) VALUES (?, ?, ?, ?)",
            msg.to_row(),
        )
        conn.commit()
        msg_id = cur.lastrowid
        conn.close()
        return msg_id


def get_messages_for_client(to_client_id: bytes) -> list[Message]:
    """Fetch all pending messages for the given client."""
    with DB_LOCK:
        conn = _connect()
        cur = conn.cursor()
        cur.execute("""
            SELECT ID, ToClient, FromClient, Type, Content
            FROM messages
            WHERE ToClient = ?
            ORDER BY ID
        """, (to_client_id,))
        rows = cur.fetchall()
        conn.close()
        return [Message.from_row(r) for r in rows]


def delete_messages_for_client(to_client_id: bytes):
    """Delete all pending messages for the given client."""
    with DB_LOCK:
        conn = _connect()
        conn.execute("DELETE FROM messages WHERE ToClient = ?", (to_client_id,))
        conn.commit()
        conn.close()
