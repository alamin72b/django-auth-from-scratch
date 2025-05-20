from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect
from .helpers import get_authenticated_user,create_session,SESSION_DURATION_MINUTES,PERSISTENT_SESSION_DURATION_DAYS,log_auth_event
import bcrypt
from .db import get_connection
from .helpers import is_valid_password
import secrets
from django.core.mail import send_mail
from datetime import datetime, timedelta



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
          # Log login event here
        ip_address = request.META.get('REMOTE_ADDR', 'unknown')
        log_auth_event(user_id, 'login', ip_address)

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

    user = get_authenticated_user(request)
    if user:
        ip_address = request.META.get('REMOTE_ADDR', 'unknown')
        log_auth_event(user['id'], 'logout', ip_address)

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



def forgot_password_view(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()

        if not email:
            return render(request, 'forgot_password.html', {'error': 'Email is required.'})

        # Check if email exists and is verified
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT id, username, email_verified FROM users WHERE email = ?
            """, (email,))
            row = cur.fetchone()

        if not row:
            return render(request, 'forgot_password.html', {'error': 'No account found with that email.'})

        user_id, username, email_verified = row

        if not email_verified:
            return render(request, 'forgot_password.html', {'error': 'Please verify your email first.'})

        # Generate token
        reset_token = secrets.token_urlsafe(32)
        expiry_time = datetime.now() + timedelta(minutes=30)

        # Save token in DB
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                UPDATE users SET reset_token = ?, reset_token_expiry = ?
                WHERE id = ?
            """, (reset_token, expiry_time, user_id))
            conn.commit()

        # Compose reset link
        reset_link = f"http://localhost:8000/reset-password?token={reset_token}"

        # Send email
        subject = "Password Reset - Your App"
        message = f"Hi {username},\n\nTo reset your password, click the link below:\n{reset_link}\n\nThis link will expire in 30 minutes.\n\nThanks!"
        send_mail(subject, message, None, [email])

        print(f"[DEBUG] Password reset link: {reset_link}")  # For dev testing

        return render(request, 'forgot_password.html', {'success': '📩 Reset link sent to your email.'})

    return render(request, 'forgot_password.html')










def reset_password_view(request):
    token = request.GET.get('token') or request.POST.get('token')

    if not token:
        return render(request, 'reset_password.html', {'error': 'Reset token is missing or invalid.'})

    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, reset_token_expiry FROM users WHERE reset_token = ?
        """, (token,))
        row = cur.fetchone()

    if not row:
        return render(request, 'reset_password.html', {'error': 'Invalid or expired token.'})

    user_id, reset_token_expiry = row

    # Check token expiry
    expiry_dt = datetime.strptime(reset_token_expiry, "%Y-%m-%d %H:%M:%S.%f")
    if datetime.now() > expiry_dt:
        return render(request, 'reset_password.html', {'error': 'Token has expired. Please request a new one.'})

    if request.method == 'POST':
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')

        if password != confirm_password:
            return render(request, 'reset_password.html', {
                'error': 'Passwords do not match.', 'token': token
            })

        valid, message = is_valid_password(password)
        if not valid:
            return render(request, 'reset_password.html', {
                'error': message, 'token': token
            })

        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                UPDATE users
                SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL
                WHERE id = ?
            """, (password_hash, user_id))
            conn.commit()

        return render(request, 'reset_password.html', {
            'success': '✅ Your password has been reset successfully.'
        })

    return render(request, 'reset_password.html', {'token': token})