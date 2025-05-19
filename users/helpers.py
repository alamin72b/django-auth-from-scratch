import secrets
from datetime import datetime, timedelta
from .db import get_connection
import re

SESSION_DURATION_MINUTES = 60
PERSISTENT_SESSION_DURATION_DAYS = 7

def create_session(user_id, persistent=False):
    session_token = secrets.token_urlsafe(32)

    if persistent:
        expires_at = datetime.now() + timedelta(days=PERSISTENT_SESSION_DURATION_DAYS)
        is_persistent = 1
    else:
        expires_at = datetime.now() + timedelta(minutes=SESSION_DURATION_MINUTES)
        is_persistent = 0

    print(f"[create_session] user_id={user_id}, persistent={persistent}")
    print(f"[create_session] session_token={session_token}")
    print(f"[create_session] expires_at={expires_at}, is_persistent={is_persistent}")

    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO sessions (user_id, session_token, expires_at, is_persistent)
            VALUES (?, ?, ?, ?)
        """, (user_id, session_token, expires_at, is_persistent))
        conn.commit()

    return session_token


def get_authenticated_user(request):
    session_token = request.COOKIES.get('session_token')
    print(f"[get_authenticated_user] session_token from cookie: {session_token}")
    if not session_token:
        print("[get_authenticated_user] No session_token cookie found")
        return None

    try:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT users.id, users.username, users.email, sessions.expires_at, sessions.is_persistent
                FROM sessions
                JOIN users ON sessions.user_id = users.id
                WHERE sessions.session_token = ?
            """, (session_token,))
            row = cur.fetchone()

        if not row:
            print("[get_authenticated_user] No matching session found in DB")
            return None

        user_id, username, email, expires_at, is_persistent = row
        print(f"[get_authenticated_user] Found session: user_id={user_id}, username={username}, expires_at={expires_at}, is_persistent={is_persistent}")

        expires_at_dt = datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S.%f')
        print(f"[get_authenticated_user] Parsed expires_at: {expires_at_dt}, now: {datetime.now()}")

        if datetime.now() > expires_at_dt:
            print("[get_authenticated_user] Session expired, deleting...")
            with get_connection() as conn:
                cur = conn.cursor()
                cur.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
                conn.commit()
            return None

        print("[get_authenticated_user] Session valid, returning user info")
        return {
            'id': user_id,
            'username': username,
            'email': email,
            'is_persistent': is_persistent,
        }

    except Exception as e:
        print(f"[get_authenticated_user] Exception occurred: {e}")
        return None





def is_valid_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter."
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit."
    return True, ""
