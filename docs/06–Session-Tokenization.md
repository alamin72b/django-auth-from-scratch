
# 06 – Manual Login and Session Tokenization

In this chapter, we build a **manual login system with secure session management** from scratch, without relying on Django's built-in authentication or session frameworks.  

We cover:

- User authentication using raw SQL and bcrypt  
- Generating and storing secure random session tokens  
- Setting cookies safely with expiration and `HttpOnly` flags  
- Validating sessions on each request, including expiration checks  
- Preventing common pitfalls like redirect loops and timestamp parsing errors  

---

## Step 1: Create the Sessions Table in the Database

To securely manage user sessions, we create a new table called `sessions`. This table holds information about active login sessions:

- **id**: Unique session ID  
- **user_id**: Foreign key linking to the user  
- **session_token**: A long, random, unguessable string identifying the session  
- **expires_at**: When the session expires and is no longer valid  
- **created_at**: When the session was created  

**File:** `users/db.py`

```python
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
````

> **Important:**
> Run this once during your initial database setup to create the table.

---

## Step 2: Generate Secure Session Tokens

When a user logs in successfully, we generate a **secure random session token**. This token will be stored in the database and sent to the user as a cookie.

**File:** `users/helpers.py`

```python
import secrets
from datetime import datetime, timedelta
from .db import get_connection

SESSION_DURATION_MINUTES = 60  # Sessions last for 60 minutes

def create_session(user_id):
    # Generate a random session token
    session_token = secrets.token_urlsafe(32)

    # Calculate when the session should expire
    expires_at = datetime.utcnow() + timedelta(minutes=SESSION_DURATION_MINUTES)

    # Insert the session into the database
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO sessions (user_id, session_token, expires_at)
            VALUES (?, ?, ?)
        """, (user_id, session_token, expires_at))
        conn.commit()

    return session_token
```

**Why `secrets.token_urlsafe(32)`?**

* It generates a **cryptographically strong random string** that’s safe for URLs and cookies.
* The 32-byte length ensures the token is hard to guess or brute force.

---

## Step 3: Validate Sessions on Every Request

Every time a user accesses a protected page, we validate their session by checking the token stored in their cookie:

* Confirm the token exists in the database
* Check that the session has not expired
* If expired, delete the session
* Return the user’s info if valid, or `None` otherwise

**File:** `users/helpers.py`

```python
from datetime import datetime

def get_authenticated_user(request):
    session_token = request.COOKIES.get('session_token')
    if not session_token:
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
            return None

        user_id, username, email, expires_at = row

        # Parse the expiration timestamp including microseconds
        if datetime.utcnow() > datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S.%f'):
            # Session expired — delete it from the database
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

    except Exception:
        return None
```

---

## Step 4: Implement the Login View

When a user submits their login form:

* We fetch the user record by username or email
* Verify the password with `bcrypt`
* Create a session token and store it in the database
* Set the session token in an **HttpOnly cookie** with expiration

**File:** `users/views.py`

```python
from django.shortcuts import render, redirect
from .helpers import create_session, get_authenticated_user, SESSION_DURATION_MINUTES
import bcrypt
from .db import get_connection

def login_view(request):
    # Redirect logged-in users to home
    if get_authenticated_user(request):
        return redirect('/home/')

    if request.method == 'POST':
        identifier = request.POST.get('identifier', '').strip()
        password = request.POST.get('password', '')

        if not identifier or not password:
            return render(request, 'login.html', {'error': 'All fields are required'})

        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT id, username, password_hash FROM users
                WHERE username = ? OR email = ?
            """, (identifier, identifier))
            row = cur.fetchone()

        if not row:
            return render(request, 'login.html', {'error': 'User not found'})

        user_id, username, password_hash = row

        if not bcrypt.checkpw(password.encode(), password_hash.encode()):
            return render(request, 'login.html', {'error': 'Incorrect password'})

        session_token = create_session(user_id)

        response = redirect('/home/')
        response.set_cookie(
            'session_token',
            session_token,
            httponly=True,           # Prevent access via JavaScript
            secure=False,            # Set to True if using HTTPS in production
            max_age=SESSION_DURATION_MINUTES * 60  # Expire after set time
        )
        return response

    return render(request, 'login.html')
```

---

## Step 5: Implement the Logout View

To log a user out:

* Delete the session record from the database
* Remove the session token cookie from the browser
* Redirect to the login page

**File:** `users/views.py`

```python
from django.http import HttpResponseRedirect
from .db import get_connection

def logout_view(request):
    session_token = request.COOKIES.get('session_token')
    response = HttpResponseRedirect('/login/')

    if session_token:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
            conn.commit()

        response.delete_cookie('session_token')

    return response
```

---

## Step 6: Protect Views by Validating Sessions

Before rendering protected pages, check if the user is authenticated by validating their session token:

**File:** `users/views.py`

```python
from django.shortcuts import render, redirect
from .helpers import get_authenticated_user

def home_view(request):
    user = get_authenticated_user(request)
    if not user:
        return redirect('/login/')

    return render(request, 'home.html', {'username': user['username']})
```

---

## ❓ Q\&A — What I Learned

**❓ Why store only a random session token in cookies instead of user info?**
Storing only a random token makes it impossible for users to modify their identity or escalate privileges by tampering with cookies.

---

**❓ How does `secrets.token_urlsafe(32)` help security?**
It generates a long, cryptographically strong, unpredictable string, making session hijacking very difficult.

---

**❓ Why check session expiration on every request?**
To log out users automatically when their session expires and keep the database clean by removing expired sessions.

---

**❓ Why parse timestamps with microseconds (`%f`)?**
Because the database stores timestamps including fractional seconds, which must be parsed correctly to avoid errors.

---

**❓ What does the `HttpOnly` cookie flag do?**
It prevents JavaScript from accessing cookies, reducing vulnerability to cross-site scripting (XSS) attacks.

---

**❓ Why did I get redirect loops before?**
Because the login view checked only if the cookie existed, not if the session was valid and unexpired. Always validate the session with `get_authenticated_user()` before redirecting logged-in users.

---

## ✅ Summary of Today’s Work

| Feature                | Description                                   |
| ---------------------- | --------------------------------------------- |
| Secure session tokens  | Generated randomly and stored in DB           |
| Session expiration     | Sessions expire after 60 minutes              |
| Cookie management      | Session tokens sent as `HttpOnly` cookies     |
| Login/logout workflows | Sessions created and deleted in DB            |
| Session validation     | Checked on every request, expiration enforced |

---

## 🔜 Next Steps

* Add "Remember Me" functionality for persistent sessions
* Improve cookie security with `Secure` flag and SameSite policies
* Implement password reset and email verification flows

