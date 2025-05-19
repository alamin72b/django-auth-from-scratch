
# 08 – Cookie Security and Password Validation Enhancements

In this chapter, we strengthen our manual authentication system by improving cookie security and adding essential password validation with a confirm password check.

We cover:

* Setting secure cookie attributes for session tokens
* Implementing basic server-side password validation rules
* Adding confirm password verification in the registration process
* Handling error messages and feedback in the user interface

---

## Step 1: Set Secure Attributes on Session Cookies

To protect session cookies from common web attacks, we configure cookies with the following flags:

* **HttpOnly:** Prevents JavaScript access to cookies (mitigates XSS attacks)
* **Secure:** Ensures cookies are sent only over HTTPS (set to `True` in production)
* **SameSite='Lax':** Restricts cookies from being sent on some cross-site requests, reducing CSRF risks

**File:** `users/views.py` (Login view snippet)

```python
response.set_cookie(
    'session_token',
    session_token,
    httponly=True,            # JavaScript cannot access cookie
    secure=True,              # Only sent over HTTPS (set to False during local dev)
    samesite='Lax',           # Prevents CSRF by restricting cross-site cookie sending
    max_age=SESSION_DURATION_MINUTES * 60,
)
```

> **Note:**
>
> * Use `secure=True` only if your app is deployed with HTTPS.
> * `SameSite='Lax'` balances security and usability, allowing cookies on safe navigations.

---

## Step 2: Add Basic Password Validation

We create a helper function `is_valid_password()` to enforce simple yet effective password rules:

* Password must be **at least 8 characters** long
* Must contain **at least one letter**
* Must contain **at least one digit**

This prevents weak passwords and improves overall security.

**File:** `users/helpers.py`

```python
import re

def is_valid_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter."
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit."
    return True, ""
```

---

## Step 3: Integrate Password Validation into Registration

We update the registration view to:

* Check that all required fields are filled
* Validate the password using `is_valid_password()`
* Provide meaningful error messages if validation fails

**File:** `users/views.py` (Register view snippet)

```python
from .helpers import is_valid_password

def register_view(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')

        # Check all fields are present
        if not username or not email or not password or not confirm_password:
            return render(request, 'register.html', {'error': 'All fields are required'})

        # Check passwords match
        if password != confirm_password:
            return render(request, 'register.html', {'error': 'Passwords do not match'})

        # Validate password strength
        valid, message = is_valid_password(password)
        if not valid:
            return render(request, 'register.html', {'error': message})

        # Proceed with password hashing and user insertion...
        # (rest of your existing code)
```

---

## Step 4: Update Registration Form for Confirm Password

We modify the HTML form to include a confirm password field to verify user input:

**File:** `templates/register.html`

```html
<form method="POST">
  {% csrf_token %}
  
  <label>Username:</label><br>
  <input type="text" name="username" required><br><br>
  
  <label>Email:</label><br>
  <input type="email" name="email" required><br><br>
  
  <label>Password:</label><br>
  <input type="password" name="password" required><br><br>
  
  <label>Confirm Password:</label><br>
  <input type="password" name="confirm_password" required><br><br>
  
  <button type="submit">Register</button>

  {% if error %}
    <p style="color: red;">{{ error }}</p>
  {% endif %}
  
  {% if success %}
    <p style="color: green;">{{ success }}</p>
  {% endif %}
</form>
```

---

## ❓ Q\&A — What I Learned

**❓ Why set `HttpOnly` and `Secure` flags on cookies?**
They protect session cookies from being stolen via cross-site scripting and ensure cookies are sent only over encrypted HTTPS connections.

---

**❓ Why use `SameSite='Lax'` for cookies?**
It mitigates cross-site request forgery by restricting cookies from being sent on unsafe cross-site requests, while allowing normal navigation flows.

---

**❓ Why check if passwords match?**
To catch user typos and ensure they know exactly what password they registered with.

---

**❓ Why have basic password rules?**
To stop users from choosing very weak passwords like “12345” that are easily cracked.

---

## ✅ Summary of Today’s Work

| Feature                    | Description                                    |
| -------------------------- | ---------------------------------------------- |
| Secure cookie flags        | `HttpOnly=True`, `Secure=True`, `SameSite=Lax` |
| Password validation helper | Checks length, letter, and digit presence      |
| Confirm password field     | Double-checks password input during signup     |
| User feedback on errors    | Shows helpful messages on invalid inputs       |

