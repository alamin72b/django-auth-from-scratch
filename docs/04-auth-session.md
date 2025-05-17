
# 04 – Manual Login, Logout, and Session Handling (No Django Auth)

This chapter documents how I implemented login, logout, and manual session management in Django — completely from scratch, with no use of Django’s authentication system or session framework.

I used:
- Raw SQL to find users
- `bcrypt` to verify passwords
- Cookies to track session state
- Function-based views only

---

## ✅ What I Built

- A secure login form using plain HTML
- A login view that looks up users and checks credentials
- Manual session logic using cookies (`set_cookie`, `request.COOKIES`)
- A logout view that clears the cookies
- A `/home/` page that is only accessible if the user is “logged in”

---

## 🔐 Login Form (HTML)

📄 File: `users/templates/login.html`

```html
<form method="POST">
    {% csrf_token %}

    <label>Username or Email:</label><br>
    <input type="text" name="identifier" required><br><br>

    <label>Password:</label><br>
    <input type="password" name="password" required><br><br>

    <button type="submit">Login</button>
</form>

{% if error %}
    <p style="color: red;">{{ error }}</p>
{% endif %}

{% if success %}
    <p style="color: green;">{{ success }}</p>
{% endif %}
````

---

## 🔧 Login View

📄 File: `users/views.py`

```python
def login_view(request):
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

        response = redirect('/home/')
        response.set_cookie('user_id', str(user_id))
        response.set_cookie('username', username)
        return response

    return render(request, 'login.html')
```

---

## 🚪 Logout View

📄 File: `users/views.py`

```python
def logout_view(request):
    response = HttpResponseRedirect('/login/')
    response.delete_cookie('user_id')
    response.delete_cookie('username')
    return response
```

* Clears both login cookies
* Redirects back to the login page

---

## 🏠 Home View (Protected Page)

📄 File: `users/views.py`

```python
def home_view(request):
    user_id = request.COOKIES.get('user_id')
    username = request.COOKIES.get('username')

    if not user_id or not username:
        return redirect('/login/')

    return render(request, 'home.html', {
        'username': username
    })
```

---

## 🖼️ Home Page Template

📄 File: `users/templates/home.html`

```html
<h1>Welcome, {{ username }}!</h1>
<p>This is your dashboard.</p>
<a href="/logout/"><button>Logout</button></a>
```

Only users with both cookies set will see this. Others will be redirected to `/login/`.

---

## 🌐 URL Configuration

📄 File: `users/urls.py`

```python
from .views import register_view, login_view, logout_view, home_view

urlpatterns = [
    path('register/', register_view),
    path('login/', login_view),
    path('logout/', logout_view),
    path('home/', home_view),
]
```

---

## ❓ Q\&A: Doubts I Had and What I Learned

---

### ❓ What does `cur.fetchone()` actually return?

**Answer:**
It returns the **first row** from the SQL query as a tuple. Example:

```python
(3, "alice", "$2b$12...hashed...")
```

If no user matches the query, it returns `None`.

---

### ❓ What does `set_cookie()` do, exactly?

**Answer:**
It tells the browser:

> “Store this value and send it back on every request.”

So when I do:

```python
response.set_cookie('user_id', '3')
```

The browser stores that value. On the next request, I can access it via:

```python
request.COOKIES['user_id']  # "3"
```

---

### ❓ Why do I set both `user_id` and `username`?

* `user_id` is the unique identifier I can use internally (for future queries).
* `username` is just for display (e.g. "Welcome, {{ username }}").

Both are stored in cookies. In a real system, you might only store a session token and fetch user data on demand.

---

### ❓ Can cookies be trusted?

No — cookies can be easily modified by the user.

This is why:

* You should **validate** cookie values on the server (e.g. `user_id` must exist)
* Later, you can **sign or encrypt cookies** to detect tampering

Right now, this system is minimal — but I understand the tradeoff.

---

### ❓ Isn’t this what Django’s sessions do?

Yes — Django’s session system:

* Stores session data on the server (e.g. database, file)
* Sends only a secure `sessionid` cookie to the client
* Prevents tampering and adds extra security

But doing this manually has helped me understand how it all works behind the scenes.

---

## 🧠 Summary

| Feature        | Implementation                     |
| -------------- | ---------------------------------- |
| Login form     | Raw HTML + CSRF                    |
| Password check | `bcrypt.checkpw()`                 |
| Cookie set     | `response.set_cookie()`            |
| Session check  | `request.COOKIES[...]`             |
| Logout         | `delete_cookie()`                  |
| Access control | Redirect based on cookie existence |

---

## 🔜 What’s Next

* Create a session helper or middleware-like function
* Add cookie security (`httponly`, `secure`, `max_age`)
* Create flash messages on login/logout
* Document how to secure and validate sessions further
