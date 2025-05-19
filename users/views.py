from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect
from .helpers import get_authenticated_user,create_session,SESSION_DURATION_MINUTES
import bcrypt
from .db import get_connection


def register_view(request):
    """
    Handles user registration.

    - On GET: Renders the registration form.
    - On POST: Validates and registers a new user.
    """
    if request.method == 'POST':
        # Extract and sanitize input
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')

        # Basic validation
        if not username or not email or not password:
            return render(request, 'register.html', {'error': 'All fields are required'})

        # Hash the password using bcrypt
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        try:
            # Insert new user into the database
            with get_connection() as conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO users (username, email, password_hash)
                    VALUES (?, ?, ?)
                """, (username, email, password_hash))
                conn.commit()
            return render(request, 'register.html', {'success': '✅ User registered successfully!'})
        except Exception as e:
            # Handle duplicate username/email
            if 'UNIQUE constraint failed' in str(e):
                return render(request, 'register.html', {'error': 'Username or email already taken'})
            # Handle other DB-related errors
            return render(request, 'register.html', {'error': f'Error: {str(e)}'})

    # Render registration form on GET
    return render(request, 'register.html')



def login_view(request):
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
            httponly=True,
            secure=False,  # Set True if using HTTPS in production
            max_age=SESSION_DURATION_MINUTES * 60
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
