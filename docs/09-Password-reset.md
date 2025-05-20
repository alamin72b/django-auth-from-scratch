
# 🔐 Password Reset via Email Token (Manual Django Authentication System)

---

## 📌 Overview

This module allows users to **reset their password via email** without using Django's built-in `auth` system or session framework. The entire system uses:

* Raw SQL with SQLite
* Secure token generation with `secrets`
* Bcrypt password hashing
* Manual session management
* Email delivery using SMTP

---

## ✅ Features Implemented

| Feature                          | Description                                                    |
| -------------------------------- | -------------------------------------------------------------- |
| `forgot-password/` view          | Collects email and sends reset link if email is verified       |
| Secure token generation          | Generates a one-time token with expiry for password reset      |
| Token + expiry storage in DB     | Stored in `users` table                                        |
| Email with reset link            | Plain text reset email sent using `send_mail()`                |
| `reset-password/` view           | Lets user set a new password if token is valid and not expired |
| Password validation and hashing  | Ensures strong password and uses `bcrypt` before storing       |
| Token invalidation after success | Token is deleted after reset to prevent reuse                  |
| "Forgot Password?" in login form | Accessible link for users who forget credentials               |

---

## 🗃️ Database Schema Changes

You need to add two new fields to the `users` table:

```sql
ALTER TABLE users ADD COLUMN reset_token TEXT;
ALTER TABLE users ADD COLUMN reset_token_expiry TIMESTAMP;
```

If using Python, define and run this once:

```python
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
```

---

## 📤 Email Configuration (`settings.py`)

Make sure your Django `settings.py` includes this setup to send real emails via Gmail:

```python
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'your.email@gmail.com'
EMAIL_HOST_PASSWORD = 'your_app_password'  # use App Password if 2FA is on
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER
```

---

## 🧠 Logic Flow

### 1. Forgot Password

* User visits `/forgot-password/` and enters their email.
* If the email is valid and verified, a **token** is generated and saved to DB.
* A **reset link** is sent to their inbox with that token.

### 2. Reset Password

* User clicks the reset link: `/reset-password/?token=...`
* If the token is found and not expired, the reset form is shown.
* User enters new password → it's validated, hashed, saved.
* Token is cleared.

---

## 🧾 Full Code (With Explanations)

---

### 🔸 `views.py` – Forgot Password

```python
import secrets
import bcrypt
from datetime import datetime, timedelta
from django.shortcuts import render, redirect
from django.core.mail import send_mail
from .db import get_connection
from .helpers import is_valid_password

def forgot_password_view(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()

        if not email:
            return render(request, 'forgot_password.html', {'error': 'Email is required.'})

        # Check if user exists and email is verified
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, username, email_verified FROM users WHERE email = ?", (email,))
            row = cur.fetchone()

        if not row:
            return render(request, 'forgot_password.html', {'error': 'No account found with that email.'})

        user_id, username, email_verified = row
        if not email_verified:
            return render(request, 'forgot_password.html', {'error': 'Please verify your email first.'})

        # Generate secure reset token
        reset_token = secrets.token_urlsafe(32)
        expiry = datetime.now() + timedelta(minutes=30)

        # Save token to DB
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?",
                        (reset_token, expiry, user_id))
            conn.commit()

        # Compose email
        reset_link = f"http://localhost:8000/reset-password?token={reset_token}"
        subject = "Password Reset - Your App"
        message = f"Hi {username},\n\nTo reset your password, click this link:\n{reset_link}\n\nLink expires in 30 minutes."

        send_mail(subject, message, None, [email])
        print(f"[DEBUG] Sent reset link: {reset_link}")

        return render(request, 'forgot_password.html', {'success': '📩 Check your email for the reset link.'})

    return render(request, 'forgot_password.html')
```

---

### 🔸 `views.py` – Reset Password

```python
def reset_password_view(request):
    token = request.GET.get('token') or request.POST.get('token')

    if not token:
        return render(request, 'reset_password.html', {'error': 'Missing reset token.'})

    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, reset_token_expiry FROM users WHERE reset_token = ?", (token,))
        row = cur.fetchone()

    if not row:
        return render(request, 'reset_password.html', {'error': 'Invalid or expired token.'})

    user_id, expiry = row
    expiry_dt = datetime.strptime(expiry, "%Y-%m-%d %H:%M:%S.%f")
    if datetime.now() > expiry_dt:
        return render(request, 'reset_password.html', {'error': 'Token has expired.'})

    if request.method == 'POST':
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')

        if password != confirm_password:
            return render(request, 'reset_password.html', {'error': 'Passwords do not match.', 'token': token})

        valid, message = is_valid_password(password)
        if not valid:
            return render(request, 'reset_password.html', {'error': message, 'token': token})

        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?",
                        (password_hash, user_id))
            conn.commit()

        return render(request, 'reset_password.html', {'success': '✅ Password reset successful.'})

    return render(request, 'reset_password.html', {'token': token})
```

---

## 🧩 Template Files

### 📄 `forgot_password.html`

```html
<form method="POST">
  {% csrf_token %}
  <label>Email:</label><br>
  <input type="email" name="email" required><br><br>
  <button type="submit">Send Reset Link</button>
</form>

{% if error %}
  <p style="color: red;">{{ error }}</p>
{% endif %}
{% if success %}
  <p style="color: green;">{{ success }}</p>
{% endif %}
```

---

### 📄 `reset_password.html`

```html
{% if error %}
  <p style="color: red;">{{ error }}</p>
{% endif %}
{% if success %}
  <p style="color: green;">{{ success }}</p>
{% else %}
<form method="POST">
  {% csrf_token %}
  <input type="hidden" name="token" value="{{ token }}">
  <label>New Password:</label><br>
  <input type="password" name="password" required><br><br>
  <label>Confirm Password:</label><br>
  <input type="password" name="confirm_password" required><br><br>
  <button type="submit">Reset Password</button>
</form>
{% endif %}
```

---

### 📝 `login.html` — Add link for forgot password

```html
<p><a href="{% url 'forgot_password' %}">Forgot Password?</a></p>
```

---

## 🌐 `urls.py` — Route Setup

```python
from .views import forgot_password_view, reset_password_view

urlpatterns += [
    path('forgot-password/', forgot_password_view, name='forgot_password'),
    path('reset-password/', reset_password_view, name='reset_password'),
]
```

---

## 🧠 Lessons Learned

* Secure token-based flows can be built manually without Django's auth
* Email sending and link-based workflows require solid token management
* Always expire and clear sensitive tokens after use
* Manual session and user flow = more control but more responsibility
