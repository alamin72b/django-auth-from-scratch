
# 05 – Access Control Helper: Centralizing Login Checks (Manual Django Auth)

This chapter documents how I created a **manual helper function** to centralize authentication checks across my Django views. Instead of repeating cookie reading and validation everywhere, I wrapped this logic into one reusable function.

I wrote this for **deeper understanding** of auth flow, clean code, and easier maintenance — still without using Django’s built-in auth or session tools.

---

## ✅ What I Built

- `get_authenticated_user(request)` helper function
- It reads and validates `user_id` and `username` cookies
- Checks user existence and consistency in the database
- Returns user info as a dictionary or `None` if not authenticated
- Refactored protected views to use this helper for cleaner access control

---

## 🔧 Helper Function: `get_authenticated_user`

📄 File: `users/helpers.py`

```python
from .db import get_connection

def get_authenticated_user(request):
    """
    Return user dict if logged in and valid, else None.
    Steps:
    1. Read cookies for user_id and username.
    2. Return None if missing.
    3. Query DB to verify user exists and username matches.
    4. Return user info dict or None.
    """
    user_id = request.COOKIES.get('user_id')
    username = request.COOKIES.get('username')

    if not user_id or not username:
        return None

    try:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,))
            row = cur.fetchone()

        if not row or row[1] != username:
            return None

        return {
            'id': row[0],
            'username': row[1],
            'email': row[2]
        }

    except Exception:
        return None
````

---

## 🔄 Refactoring a Protected View to Use the Helper

📄 File: `users/views.py`

**Before:**

```python
def home_view(request):
    user_id = request.COOKIES.get('user_id')
    username = request.COOKIES.get('username')

    if not user_id or not username:
        return redirect('/login/')

    return render(request, 'home.html', {'username': username})
```

**After:**

```python
from .helpers import get_authenticated_user

def home_view(request):
    user = get_authenticated_user(request)
    if not user:
        return redirect('/login/')

    return render(request, 'home.html', {'username': user['username']})
```

---

## ❓ Q\&A: What I Wondered and Learned

---

### ❓ Why do I need to check both `user_id` and `username` cookies?

Because cookies can be edited by the user. Validating both values against the database protects against tampering and impersonation.

---

### ❓ What happens if the cookies are missing or invalid?

`get_authenticated_user` returns `None`, signaling the user is not logged in. Views can then redirect to the login page.

---

### ❓ Why return a dictionary of user data?

Returning a dict like `{ 'id': ..., 'username': ..., 'email': ... }` makes the code more readable and easier to work with than raw SQL tuples.

---

### ❓ What if the database query fails?

The helper catches exceptions and safely returns `None` so the app won’t crash unexpectedly.

---

### ❓ How is this different from Django’s session system?

Django sessions store data server-side and send a secure session ID cookie. Here, all info is in cookies, so it’s less secure and requires careful validation.

---

## 🧠 What I’ve Learned

* Centralizing cookie reading and validation makes code cleaner and less error-prone
* Cookies are not fully trustworthy, so server-side validation is mandatory
* Returning structured data from helpers improves readability
* Defensive coding (try-except) improves robustness

---

## 🔜 What’s Next

* Refactor other protected views to use `get_authenticated_user`
* Build a decorator for automatic login-required enforcement
* Add cookie security flags (`httponly`, `secure`, `max_age`)
* Explore storing sessions server-side for better security

---

This helper is a key milestone in my manual auth journey — simplifying my views and deepening my understanding of authentication flows.

