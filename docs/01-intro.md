
# 01 – Project Setup

This chapter documents the setup of the Django project for my manual authentication system. I'm building everything from scratch — including raw SQL, bcrypt password hashing, and manual session handling — using Django **only as a web framework**, not as an authentication engine.

---

## 🧱 Goals

- Use Django only for routing, HTTP handling, and template rendering
- Build user authentication manually
- Avoid all Django-provided shortcuts (admin, auth views, models)

---

## ✅ Step 1: Create the GitHub Repository

I created a new public repository:

```

django-auth-from-scratch

````

This is where I’ll track everything: code, learning notes, and documentation.

---

## ✅ Step 2: Initialize Virtual Environment

I created a Python virtual environment to isolate dependencies:

```bash
python3 -m venv venv
source venv/bin/activate  # macOS/Linux
# venv\Scripts\activate   # Windows
````

---

## ✅ Step 3: Install Required Packages

```bash
pip install django bcrypt
```

I saved the dependencies:

```bash
pip freeze > requirements.txt
```

---

## ✅ Step 4: Create the Django Project

Inside the root of the Git repo:

```bash
django-admin startproject config .
```

> The dot (`.`) means: create the project in the **current directory**.

This created the default Django project layout in a folder called `config/`.

---

## ✅ Step 5: Create the `users` App

```bash
python manage.py startapp users
```

This is where I’ll write all authentication-related code manually.

---

## ✅ Step 6: Register the App in Django Settings

I edited `config/settings.py` and added `'users'` to the `INSTALLED_APPS` list:

```python
INSTALLED_APPS = [
    # ...
    'users',
]
```

---

## ✅ Step 7: Run the Development Server

To make sure everything works:

```bash
python manage.py runserver
```

The project launched at:

```
http://127.0.0.1:8000/
```

No errors. Ready to move forward.

---

## 🔜 Next Up

In the next step, I’ll:

* Skip Django’s model system
* Create a raw SQLite database
* Define the `users` table with raw SQL
* Begin handling user registration manually

→ [Go to Chapter 02 – Creating a Raw SQLite User Table](02-db.md)


