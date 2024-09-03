from django.urls import path
from . import views

urlpatterns = [
    path("profile/", views.user_profile, name="user_profile"),
    path("register/", views.user_register, name="user_register"),
    path("login/", views.user_login, name="user_login"),
    path("logout/", views.user_logout, name="user_logout"),
    path("change-email/", views.user_change_email, name="user_change_email"),
    path("reset-password/", views.reset_password, name="reset_password"),
    path("send/change-email/", views.send_change_email_mail, name="send_change"),
    path("send/register/", views.send_register_mail, name="send_register"),
    path("verify/", views.VerifyEmail.as_view(), name="verify_email"),
    path("active/", views.ActivateUser.as_view(), name="activate_user"),
]
