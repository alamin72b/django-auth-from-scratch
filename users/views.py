from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect
from .helpers import get_authenticated_user,create_session,SESSION_DURATION_MINUTES,PERSISTENT_SESSION_DURATION_DAYS
import bcrypt
from .db import get_connection
from .helpers import is_valid_password
import secrets
from django.core.mail import send_mail

def register_view(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')

        if not username or not email or not password or not confirm_password:
            return render(request, 'register.html', {'error': 'All fields are required'})

        if password != confirm_password:
            return render(request, 'register.html', {'error': 'Passwords do not match'})

        valid, message = is_valid_password(password)
        if not valid:
            return render(request, 'register.html', {'error': message})

        # Generate a secure email verification token
        email_verification_token = secrets.token_urlsafe(24)

        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        try:
            with get_connection() as conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO users (username, email, password_hash, email_verification_token, email_verified)
                    VALUES (?, ?, ?, ?, 0)
                """, (username, email, password_hash, email_verification_token))
                conn.commit()

            # Compose verification link
            verification_link = f"http://localhost:8000/verify-email?token={email_verification_token}"

            # Send verification email
            subject = 'Please verify your email address'
            message = f'Hi {username},\n\nPlease click the link below to verify your email address:\n{verification_link}\n\nThank you!'
            from_email = None  # uses DEFAULT_FROM_EMAIL from settings.py
            recipient_list = [email]

            send_mail(subject, message, from_email, recipient_list, fail_silently=False)

            print(f"[DEBUG] Verification link for {email}: {verification_link}")

            return render(request, 'register.html', {
                'success': '✅ User registered successfully! Please check your email to verify your account.'
            })

        except Exception as e:
            if 'UNIQUE constraint failed' in str(e):
                return render(request, 'register.html', {'error': 'Username or email already taken'})
            return render(request, 'register.html', {'error': f'Error: {str(e)}'})

    return render(request, 'register.html')


def verify_email_view(request):
    token = request.GET.get('token')
    if not token:
        return render(request, 'verify_email.html', {'error': 'Invalid or missing token.'})

    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, email_verified FROM users WHERE email_verification_token = ?", (token,))
        user = cur.fetchone()

        if not user:
            return render(request, 'verify_email.html', {'error': 'Invalid verification token.'})

        user_id, email_verified = user

        if email_verified:
            return render(request, 'verify_email.html', {'message': 'Email already verified.'})

        cur.execute("UPDATE users SET email_verified = 1 WHERE id = ?", (user_id,))
        conn.commit()

    return render(request, 'verify_email.html', {'message': 'Your email has been verified successfully!'})





def login_view(request):
    if get_authenticated_user(request):
        return redirect('/home/')

    if request.method == 'POST':
        identifier = request.POST.get('identifier', '').strip()
        password = request.POST.get('password', '')
        remember_me = request.POST.get('remember_me') == 'on'

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

        session_token = create_session(user_id, persistent=remember_me)

        response = redirect('/home/')

        max_age_seconds = (PERSISTENT_SESSION_DURATION_DAYS * 24 * 60 * 60) if remember_me else (SESSION_DURATION_MINUTES * 60)

        response.set_cookie(
            'session_token',
            session_token,
            httponly=True,
            secure=True,  # Use True in production with HTTPS
            samesite='Lax',
            max_age=max_age_seconds,
        )


        return response

    return render(request, 'login.html')

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

def home_view(request):
    """
    Renders the home page for authenticated users.

    - Redirects to login if the user is not authenticated.
    """
    user = get_authenticated_user(request)
    if not user:
        return redirect('/login/')

    return render(request, 'home.html', {'username': user['username']})
