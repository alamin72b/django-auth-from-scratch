from django.urls import path
from .views import register_view, login_view, logout_view, home_view, verify_email_view

urlpatterns = [
    path('register/', register_view, name='register'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('home/', home_view, name='home'),
    path('verify-email/', verify_email_view, name='verify_email'),  # ✅ Add this
]
