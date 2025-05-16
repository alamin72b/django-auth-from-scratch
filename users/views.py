from django.shortcuts import render

# Create your views here.
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
