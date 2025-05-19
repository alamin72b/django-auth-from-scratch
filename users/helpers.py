import secrets
from datetime import datetime, timedelta
from .db import get_connection

SESSION_DURATION_MINUTES = 60  # 1 hour session timeout

def create_session(user_id):
    session_token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(minutes=SESSION_DURATION_MINUTES)

    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO sessions (user_id, session_token, expires_at)
            VALUES (?, ?, ?)
        """, (user_id, session_token, expires_at))
        conn.commit()

    return session_token

def get_authenticated_user(request):
    session_token = request.COOKIES.get('session_token')
    print("Session token from cookie:", session_token)
    if not session_token:
        print("No session token found")
        return None
    try:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT users.id, users.username, users.email, sessions.expires_at
                FROM sessions 
                JOIN users ON sessions.user_id = users.id
                WHERE sessions.session_token = ?
            """, (session_token,))
            row = cur.fetchone()

        if not row:
            print("No matching session found in DB")
            return None

        user_id, username, email, expires_at = row
        print("Session expires at:", expires_at)

        if datetime.now() > datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S.%f'):
            print("Session expired")
            with get_connection() as conn:
                cur = conn.cursor()
                cur.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
                conn.commit()
            return None

        return {
            'id': user_id,
            'username': username,
            'email': email,
        }

    except Exception as e:
        print("Exception in get_authenticated_user:", e)
        return None
