
# 06 – Manual Session Management with Persistent “Remember Me” Support

This comprehensive guide explains how to implement a **manual session management system** in Django that supports both:

- **Short-lived sessions:** Typically lasting around 1 hour, used for normal login sessions.
- **Persistent “Remember Me” sessions:** Lasting longer (e.g., 7 days), allowing users to stay logged in across browser sessions.

This system uses a **single sessions table** in your SQLite database, keeping things simple and maintainable without relying on Django’s built-in authentication or session frameworks.

---

## 1. Database Design for Session Storage

Your database will use a single `sessions` table with the following key columns:

| Column Name    | Data Type  | Description                                                              |
|----------------|------------|--------------------------------------------------------------------------|
| `id`           | INTEGER    | Primary key, auto-incremented                                            |
| `user_id`      | INTEGER    | Foreign key referencing the `users` table                               |
| `session_token`| TEXT       | A **secure random token** uniquely identifying the session              |
| `expires_at`   | TIMESTAMP  | Timestamp indicating when this session expires                           |
| `is_persistent`| INTEGER    | Flag (`0` or `1`) indicating if the session is persistent (“Remember Me”)|

---

### Why Use a Single Table with a Persistence Flag?

- **Simplifies management:** All sessions are stored in one place.
- **Eases maintenance:** One query can fetch all active sessions for a user.
- **Enhances scalability:** Easily extend or manage session types without schema changes.
- **Security:** Session tokens are server-validated; the flag simply controls expiration duration.

---

## 2. Creating a New Session: The `create_session` Function

When a user logs in, you create a new session with these steps:

### Step-by-step:

1. **Generate a secure random token:**  
   Use Python’s `secrets.token_urlsafe(32)` to create a token that’s unpredictable and safe for URLs and cookies.

2. **Set expiration based on session type:**  
   - For **persistent sessions** (when user checks “Remember Me”), set expiration to 7 days in the future.  
   - For **normal sessions**, set expiration to 1 hour.

3. **Mark persistence:**  
   Use the `is_persistent` flag (`1` for persistent, `0` for normal).

4. **Insert session into the database:**  
   Store `user_id`, `session_token`, `expires_at`, and `is_persistent`.

### Example implementation:

```python
import secrets
from datetime import datetime, timedelta
from .db import get_connection

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
    
    print(f"[create_session] Creating session for user {user_id} with token {session_token}")
    print(f"[create_session] Persistent: {persistent}, Expires at: {expires_at}")

    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO sessions (user_id, session_token, expires_at, is_persistent)
            VALUES (?, ?, ?, ?)
        """, (user_id, session_token, expires_at, is_persistent))
        conn.commit()
    
    return session_token
````

---

## 3. Validating Sessions: The `get_authenticated_user` Function

To identify the logged-in user for each incoming request, perform these actions:

### Step-by-step:

1. **Extract `session_token` from the cookie:**
   Retrieve the session token sent by the client in the `session_token` cookie.

2. **Query database for the session:**
   Join the `sessions` table with the `users` table to get user details and session metadata.

3. **Check if the session exists:**
   If the session token is invalid or missing, return `None`.

4. **Parse the expiration timestamp carefully:**
   SQLite timestamps include microseconds, so use `'%Y-%m-%d %H:%M:%S.%f'` for parsing.

5. **Check if the session has expired:**
   If expired, delete the session from the database and return `None`.

6. **Return user information if session is valid:**
   This lets your application know the current logged-in user.

### Example implementation:

```python
from datetime import datetime

def get_authenticated_user(request):
    session_token = request.COOKIES.get('session_token')
    print(f"[get_authenticated_user] Retrieved session_token: {session_token}")

    if not session_token:
        print("[get_authenticated_user] No session_token cookie present")
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
            print("[get_authenticated_user] No session found matching token")
            return None

        user_id, username, email, expires_at, is_persistent = row
        print(f"[get_authenticated_user] Found session for user {username} with expiry {expires_at}")

        expires_at_dt = datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S.%f')
        if datetime.now() > expires_at_dt:
            print("[get_authenticated_user] Session expired; deleting from DB")
            with get_connection() as conn:
                cur = conn.cursor()
                cur.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
                conn.commit()
            return None

        print("[get_authenticated_user] Session valid; returning user info")
        return {
            'id': user_id,
            'username': username,
            'email': email,
            'is_persistent': is_persistent,
        }

    except Exception as e:
        print(f"[get_authenticated_user] Exception during validation: {e}")
        return None
```

---

## 4. Why This Approach Matters

### Security

* **Random tokens:** Secure, unpredictable tokens prevent attackers from guessing session IDs.
* **Server-side session storage:** Session data is stored on the server, preventing client tampering.
* **Session expiration:** Sessions automatically expire and get cleaned up, reducing risk.

### Usability

* **Persistent sessions:** Users who select “Remember Me” stay logged in longer for convenience.
* **Short sessions:** Normal users get secure sessions that expire relatively quickly.

### Maintainability

* One table with a persistence flag is simple and efficient to manage.
* Easy to extend for additional session features in the future.

---

## 5. Important Implementation Details

### Timestamp Parsing

* SQLite timestamps include microseconds, so always use:
  `datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S.%f')`
* Failing to include microseconds results in parsing errors and failed validations.

### Cookie Security

* Set cookies as `HttpOnly` to block JavaScript access and protect against XSS attacks.
* Use the `Secure` flag when deploying over HTTPS to ensure cookies are sent securely.

### Error Handling

* Wrap database operations and parsing in `try-except` blocks.
* Log errors during development for easier troubleshooting.
* Avoid exposing errors to end users.

---

## 6. Next Steps for Integration

* **Login view:** Update to create sessions with the `persistent` flag based on “Remember Me” checkbox.
* **Logout view:** Delete the session from the database and clear cookies.
* **Protected views:** Use `get_authenticated_user` to restrict access to authenticated users.
* **Login template:** Add a “Remember Me” checkbox for users to opt-in.

---

## 7. Summary Table

| Feature                | Description                                          |
| ---------------------- | ---------------------------------------------------- |
| Session Tokens         | Secure random tokens identifying sessions            |
| Persistence Flag       | Distinguishes between normal and persistent sessions |
| Expiration Enforcement | Sessions expire and are cleaned up automatically     |
| Cookie Storage         | Tokens stored securely in `HttpOnly` cookies         |
| User Identification    | Session validated on every request                   |

---

This manual approach offers deep insight into the fundamentals of web authentication and session management, laying a strong foundation for future enhancements.

