from django.urls import path
from . import views

urlpatterns = [
    path("user/profile/", views.user_profile, name="user_profile"),
    path("user/register/", views.user_register, name="user_register"),
    path("user/login/", views.user_login, name="user_login"),
    path("user/logout/", views.user_logout, name="user_logout"),
    path("user/change-email/", views.user_change_email, name="user_change_email"),
    path("user/reset-password/", views.reset_password, name="reset_password"),
    path("user/send/change-email/", views.send_change_email_mail, name="send_change"),
    path("user/send/register/", views.send_register_mail, name="send_register"),
    path("verify/", views.VerifyEmail.as_view(), name="verify_email"),
    path("active/", views.ActivateUser.as_view(), name="activate_user"),
]
