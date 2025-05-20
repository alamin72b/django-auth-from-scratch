# 06 – Email Verification: Sending Verification Link

This chapter documents how I added the first step in our manual authentication flow: **generating a unique email verification token** after registration and **sending a verification link** by email. This keeps unverified accounts from being fully active until the user confirms their email address.

---

## ✅ What I Built

1. **Database schema extension**  
   - Added two new columns to the `users` table:  
     - `email_verification_token` (TEXT)  
     - `email_verified` (INTEGER, default 0)  
2. **Token generation**  
   - On registration, generated a secure random token with `secrets.token_urlsafe(24)`.  
3. **Token storage**  
   - Saved the token in the user’s record (`email_verification_token`) and left `email_verified = 0`.  
4. **Email dispatch**  
   - Composed a verification link:  
     ```
     http://localhost:8000/verify-email?token=<generated_token>
     ```  
   - Used Django’s `send_mail()` with SMTP settings in `settings.py` to deliver the link.  
   - Logged the link to the console for easy testing.  
5. **User feedback**  
   - After registration, showed a message:  
     > ✅ User registered successfully! Please check your email to verify your account.

---

## 🔧 Core Code Changes

### 1. Schema Update Helper

> **File:** `users/db.py` (or your migration script)

```python
def add_email_verification_columns():
    with get_connection() as conn:
        cur = conn.cursor()
        try:
            cur.execute("ALTER TABLE users ADD COLUMN email_verification_token TEXT")
        except:
            pass  # already added
        try:
            cur.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0")
        except:
            pass  # already added
        conn.commit()
````

---

### 2. SMTP Settings

> **File:** `settings.py`

```python
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'your.email@gmail.com'
EMAIL_HOST_PASSWORD = 'your_app_password'
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER
```

---

### 3. Updated Registration View

> **File:** `users/views.py`

```python
import secrets
from django.core.mail import send_mail
from django.shortcuts import render
import bcrypt
from .db import get_connection
from .helpers import is_valid_password

def register_view(request):
    if request.method == 'POST':
        username        = request.POST.get('username', '').strip()
        email           = request.POST.get('email', '').strip()
        password        = request.POST.get('password', '')
        confirm_password= request.POST.get('confirm_password', '')

        # 1. Basic validation
        if not all([username, email, password, confirm_password]):
            return render(request, 'register.html', {'error': 'All fields are required'})
        if password != confirm_password:
            return render(request, 'register.html', {'error': 'Passwords do not match'})

        # 2. Password strength check
        valid, msg = is_valid_password(password)
        if not valid:
            return render(request, 'register.html', {'error': msg})

        # 3. Generate & store verification token
        token = secrets.token_urlsafe(24)
        pwd_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        try:
            with get_connection() as conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO users
                    (username, email, password_hash, email_verification_token, email_verified)
                    VALUES (?, ?, ?, ?, 0)
                """, (username, email, pwd_hash, token))
                conn.commit()

            # 4. Send verification email
            link = f"http://localhost:8000/verify-email?token={token}"
            subject = 'Verify Your Email'
            message = (
                f'Hi {username},\n\n'
                f'Click the link below to verify your email:\n{link}\n\n'
                'If you did not register, please ignore this email.'
            )
            send_mail(subject, message, None, [email], fail_silently=False)

            # 5. Debug log
            print(f"[DEBUG] Verification link for {email}: {link}")

            return render(request, 'register.html', {
                'success': '✅ User registered! Check your email to verify the account.'
            })

        except Exception as e:
            if 'UNIQUE constraint failed' in str(e):
                return render(request, 'register.html', {'error': 'Username or email already taken'})
            return render(request, 'register.html', {'error': f'Error: {e}'})

    return render(request, 'register.html')
```

---

## 🐞 Problems I Faced

* **SMTP authentication failures** (Gmail required an App Password with 2FA).
* **No obvious error in `send_mail()`** — had to inspect Gmail’s Sent folder and enable debug-level logging to see SMTP responses.
* **Database schema changes** in sqlite3 require manual ALTER TABLE and guard against duplicate columns.

---

## 🧠 What I Learned

* How to generate and store unguessable tokens for email verification.
* Configuring Django’s SMTP email backend and handling common Gmail pitfalls.
* The importance of logging both application-level and SMTP-level events.
* Why storing the token in the user record is crucial for later verification.

---
