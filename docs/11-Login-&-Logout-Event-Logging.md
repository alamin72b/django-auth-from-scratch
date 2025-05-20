# 11. Login & Logout Event Logging — Documentation

## Overview

This document describes the implementation of login and logout event logging in the manual Django authentication system. The feature helps track user authentication activities by recording login and logout timestamps, user identification, and IP addresses.

---

## Why This Feature?

* **Audit Trail:** Maintains a secure record of when users authenticate and terminate sessions.
* **Security Monitoring:** Helps detect suspicious activities such as unauthorized access.
* **User Behavior Analysis:** Enables insights into login frequency and session duration.

---

## Database Schema

A new table `login_logs` was introduced:

| Column       | Type      | Description                                 |
| ------------ | --------- | ------------------------------------------- |
| `id`         | INTEGER   | Primary key, auto-incremented               |
| `user_id`    | INTEGER   | Foreign key to `users` table                |
| `event_type` | TEXT      | Either `'login'` or `'logout'`              |
| `ip_address` | TEXT      | IP address from which event originated      |
| `timestamp`  | TIMESTAMP | Automatically set to current time on insert |

**SQL DDL:**

```sql
CREATE TABLE IF NOT EXISTS login_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    ip_address TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

---

## Implementation Details

### Helper Function: `log_auth_event`

Encapsulates inserting an auth event record into the database.

```python
def log_auth_event(user_id, event_type, ip_address):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO login_logs (user_id, event_type, ip_address)
            VALUES (?, ?, ?)
        """, (user_id, event_type, ip_address))
        conn.commit()
```

### Login View Integration

After successful login and session creation, the login event is logged:

```python
ip_address = request.META.get('REMOTE_ADDR', 'unknown')
log_auth_event(user_id, 'login', ip_address)
```

### Logout View Integration

On logout, the logout event is logged prior to session deletion:

```python
user = get_authenticated_user(request)
if user:
    ip_address = request.META.get('REMOTE_ADDR', 'unknown')
    log_auth_event(user['id'], 'logout', ip_address)
```

---

## Testing and Verification

* Perform login and logout actions.
* Query the `login_logs` table to verify entries:

```sql
SELECT * FROM login_logs ORDER BY timestamp DESC LIMIT 10;
```

* Check that `event_type`, `user_id`, `ip_address`, and timestamps are recorded correctly.

---

## Future Improvements

* Add user-agent and device info to logs.
* Implement an admin dashboard view to browse login history.
* Add rate limiting or alerts based on suspicious patterns.

