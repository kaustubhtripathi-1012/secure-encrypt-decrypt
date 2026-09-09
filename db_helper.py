import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

DB_DIR = r"C:\Users\Public\SecureDecryptDB"
DB_PATH = os.path.join(DB_DIR, "database.db")

def init_db():
    """
    Ensure the DB directory exists and initialize the SQLite database tables.
    """
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR)
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Create messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            nonce TEXT NOT NULL,
            tag TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    """
    Establish and return a SQLite database connection with row factory enabled.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def create_user(username, password) -> bool:
    """
    Register a new user with a securely hashed password.
    Returns True if registration succeeds, False if the username already exists.
    """
    hashed = generate_password_hash(password)
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username.strip(), hashed)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def verify_user(username, password) -> dict:
    """
    Verify username and password. Returns user info if correct, otherwise None.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    row = cursor.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username.strip(),)
    ).fetchone()
    conn.close()
    
    if row and check_password_hash(row['password_hash'], password):
        return {
            'id': row['id'],
            'username': row['username']
        }
    return None

def save_message(user_id, title, ciphertext, nonce, tag, salt) -> bool:
    """
    Save an encrypted message record for a user.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """INSERT INTO messages (user_id, title, ciphertext, nonce, tag, salt)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user_id, title.strip(), ciphertext, nonce, tag, salt)
        )
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()

def get_user_messages(user_id) -> list:
    """
    Retrieve all message headers (encrypted metadata) saved by the user.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    rows = cursor.execute(
        "SELECT id, title, created_at FROM messages WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

def get_message(msg_id, user_id) -> dict:
    """
    Retrieve a specific encrypted message record after ownership check.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    row = cursor.execute(
        "SELECT id, title, ciphertext, nonce, tag, salt, created_at FROM messages WHERE id = ? AND user_id = ?",
        (msg_id, user_id)
    ).fetchone()
    conn.close()
    
    return dict(row) if row else None

def delete_message(msg_id, user_id) -> bool:
    """
    Delete a specific message after ownership check.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "DELETE FROM messages WHERE id = ? AND user_id = ?",
            (msg_id, user_id)
        )
        conn.commit()
        # Check if a row was actually deleted
        deleted = cursor.rowcount > 0
        return deleted
    except Exception:
        return False
    finally:
        conn.close()
