# users/helpers.py
from .db import get_connection

def get_authenticated_user(request):
    user_id = request.COOKIES.get('user_id')
    username = request.COOKIES.get('username')

    if not user_id or not username:
        return None

    try:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT id, username, email FROM users WHERE id = ?
            """, (user_id,))
            row = cur.fetchone()

        if not row or row[1] != username:
            return None

        return {
            'id': row[0],
            'username': row[1],
            'email': row[2]
        }

    except Exception:
        return None
