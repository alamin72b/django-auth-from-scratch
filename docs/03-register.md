

# 03 – Manual User Registration

This chapter walks through building a **manual user registration system** using:

- A raw HTML form
- Function-based Django views
- `bcrypt` for password hashing
- Raw SQL to insert users into a custom SQLite database
- No Django shortcuts (no `User`, no forms, no decorators)

---

## ✅ Step-by-Step Implementation

### 🔹 1. Registration Form Template

File: `users/templates/register.html`

```html
<form method="POST">
    {% csrf_token %}
    
    <label>Username:</label><br>
    <input type="text" name="username" required><br><br>

    <label>Email:</label><br>
    <input type="email" name="email" required><br><br>

    <label>Password:</label><br>
    <input type="password" name="password" required><br><br>

    <button type="submit">Register</button>
</form>

{% if error %}
    <p style="color: red;">{{ error }}</p>
{% endif %}
{% if success %}
    <p style="color: green;">{{ success }}</p>
{% endif %}
````

* The `{% csrf_token %}` is essential — see [CSRF Protection](#csrf-protection) below
* Success and error messages use separate variables and colors

---

### 🔹 2. Register View (Function-Based)

File: `users/views.py`

```python
import bcrypt
from django.shortcuts import render
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
```

---

### 🔹 3. Register URL

File: `users/urls.py`

```python
from django.urls import path
from .views import register_view

urlpatterns = [
    path('register/', register_view, name='register'),
]
```

Make sure it's included in `config/urls.py`:

```python
from django.urls import path, include

urlpatterns = [
    path('', include('users.urls')),
    path('admin/', admin.site.urls),
]
```

---

## 🔐 How Password Hashing Works with bcrypt

> Question: *If bcrypt uses a random salt, how can it verify passwords later?*

* The salt is **included in the hash string itself**
* `bcrypt.checkpw()` extracts that salt from the stored hash, then rehashes the input and compares
* The hash is **not reversible** — it's one-way
* bcrypt is slow **on purpose** to prevent brute-force attacks

---

## 🛡️ CSRF Protection

> Question: *Why did I get a "CSRF verification failed" error?*

Because Django blocks all unsafe POST requests unless you include:

```html
{% csrf_token %}
```

* This adds a hidden token to the form
* Django validates it before accepting the POST
* Never disable this unless you’re doing an API

---

## 💡 Why Parameterized Queries?

> Question: *Why not just write `VALUES (username, email, password_hash)` in the SQL?*

Because that would insert the column names, **not** the Python variable values.

This:

```python
cur.execute("INSERT INTO users (...) VALUES (?, ?, ?)", (username, email, password_hash))
```

* Prevents SQL injection
* Passes real values safely
* Is the only proper way to insert user input into SQL

---

## 🛠️ Tips: How to Add or Change Registration Fields

### To add a field (e.g. `full_name`):

1. Update your SQL table (use `ALTER TABLE` or drop + recreate)
2. Update the HTML form:

   ```html
   <input type="text" name="full_name" required>
   ```
3. Get it in the view:

   ```python
   full_name = request.POST.get('full_name', '').strip()
   ```
4. Add it to the SQL insert:

   ```sql
   INSERT INTO users (username, email, password_hash, full_name) VALUES (?, ?, ?, ?)
   ```

### General Advice:

* Always sanitize and validate input
* Update both HTML and view logic in sync
* Make sure new fields are included in the DB schema

---

## ✅ Summary

| What I Built     | Details                                     |
| ---------------- | ------------------------------------------- |
| Manual Form      | Plain HTML + CSRF token                     |
| View Logic       | Handles POST, hashes password, inserts user |
| Password Storage | bcrypt with random salt                     |
| SQL Insert       | Safe with parameterized query               |
| Feedback System  | Shows success and error messages            |

---

## 🔜 Next Step

→ [04 – Manual Login and Session Handling](04-login.md)

We'll:

* Take the login input
* Fetch the user from the database
* Use `bcrypt.checkpw()` to validate credentials
* Start a session manually





