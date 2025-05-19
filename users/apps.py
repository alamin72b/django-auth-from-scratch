# users/apps.py

from django.apps import AppConfig

class UsersConfig(AppConfig):
    name = 'users'

    def ready(self):
        # Import and run DB initializer
        from .db import initialize_db, add_column_if_not_exists,initialize_sessions_table,add_is_persistent_column
        initialize_db()
        add_column_if_not_exists()
        initialize_sessions_table()
        add_is_persistent_column()
