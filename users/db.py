import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / 'auth.db'

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    return conn


def initialize_db():
    """Create the users table if it doesn't exist"""
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print("✔️  Database initialized (users table ready)")

        conn.commit()



def add_column_if_not_exists():
    """Manually alters the users table to add a new column if it doesn't exist"""
    with get_connection() as conn:
        cur = conn.cursor()
        try:
            # SQLite will raise an error if you try to add a column that already exists
            cur.execute("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT 1")
            conn.commit()
            print("✅ Column 'is_active' added.")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e).lower():
                print("ℹ️ Column 'is_active' already exists. Skipping.")
            else:
                raise  # re-raise if it's a different error



def initialize_sessions_table():
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT NOT NULL UNIQUE,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        conn.commit()


def add_is_persistent_column():
    with get_connection() as conn:
        cur = conn.cursor()
        # Add the column if it doesn't exist (SQLite doesn’t support IF NOT EXISTS for ALTER TABLE, so be cautious)
        try:
            cur.execute("ALTER TABLE sessions ADD COLUMN is_persistent INTEGER DEFAULT 0")
            conn.commit()
            print("Added is_persistent column to sessions table.")
        except Exception as e:
            print("Column might already exist or error:", e)



def add_email_verification_columns():
    with get_connection() as conn:
        cur = conn.cursor()
        # Add 'email_verification_token' column if it doesn't exist
        try:
            cur.execute("ALTER TABLE users ADD COLUMN email_verification_token TEXT")
        except Exception as e:
            print("Column email_verification_token might already exist:", e)
        # Add 'email_verified' column with default 0 (false)
        try:
            cur.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0")
        except Exception as e:
            print("Column email_verified might already exist:", e)
        conn.commit()


def add_password_reset_columns():
    with get_connection() as conn:
        cur = conn.cursor()
        try:
            cur.execute("ALTER TABLE users ADD COLUMN reset_token TEXT")
        except:
            pass
        try:
            cur.execute("ALTER TABLE users ADD COLUMN reset_token_expiry TIMESTAMP")
        except:
            pass
        conn.commit()



def create_login_logs_table():
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,  -- 'login' or 'logout'
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        conn.commit()
