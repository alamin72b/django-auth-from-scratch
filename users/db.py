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
