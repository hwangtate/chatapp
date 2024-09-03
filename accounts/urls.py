from django.urls import path
from . import views

urlpatterns = [
    path("user/profile/", views.user_profile, name="user_profile"),
    path("user/register/", views.user_register, name="user_register"),
    path("active/", views.ActivateEmail.as_view(), name="activate_user"),
    path("user/login/", views.user_login, name="user_login"),
    path("user/logout/", views.user_logout, name="user_logout"),
    path("user/change-email/", views.user_change_email, name="user_change_email"),
    path("verify/", views.VerifyEmail.as_view(), name="verify_email"),
    path("user/reset-password/", views.reset_password, name="reset_password"),
]
