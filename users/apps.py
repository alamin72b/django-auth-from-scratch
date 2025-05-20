# users/apps.py

from django.apps import AppConfig

class UsersConfig(AppConfig):
    name = 'users'

    def ready(self):
        # Import and run DB initializer
        from .db import initialize_db, add_column_if_not_exists,initialize_sessions_table,add_is_persistent_column,add_email_verification_columns,add_password_reset_columns,create_login_logs_table
        initialize_db()
        add_column_if_not_exists()
        initialize_sessions_table()
        add_is_persistent_column()
        add_email_verification_columns()
        add_password_reset_columns()
        create_login_logs_table()