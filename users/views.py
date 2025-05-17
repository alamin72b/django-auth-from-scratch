from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect

import bcrypt
from .db import get_connection

def register_view(request):
    
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')

        if not username or not email or not password:
            return render(request, 'register.html', {'error': 'All fields are required'})

        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        try:
            with get_connection() as conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO users (username, email, password_hash)
                    VALUES (?, ?, ?)
                """, (username, email, password_hash))
                conn.commit()
            return render(request, 'register.html', {'success': '✅ User registered successfully!'})
        except Exception as e:
            if 'UNIQUE constraint failed' in str(e):
                return render(request, 'register.html', {'error': 'Username or email already taken'})
            return render(request, 'register.html', {'error': f'Error: {str(e)}'})

    return render(request, 'register.html')



def login_view(request):
    # 🔒 Redirect if already logged in
    if request.COOKIES.get('user_id'):
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

        # ✅ Successful login → set cookies and redirect to home
        response = redirect('/home/')
        response.set_cookie('user_id', str(user_id))
        response.set_cookie('username', username)
        return response

    return render(request, 'login.html')


def logout_view(request):
    response = HttpResponseRedirect('/login/')
    response.delete_cookie('user_id')
    response.delete_cookie('username')
    return response



def home_view(request):
    user_id = request.COOKIES.get('user_id')
    username = request.COOKIES.get('username')

    if not user_id or not username:
        return redirect('/login/')

    return render(request, 'home.html', {
        'username': username
    })