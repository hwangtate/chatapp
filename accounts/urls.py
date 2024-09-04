from django.urls import path
from . import views

urlpatterns = [
    # 일반 회원가입, 로그인
    path("profile/", views.user_profile, name="user_profile"),
    path("register/", views.user_register, name="user_register"),
    path("login/", views.user_login, name="user_login"),
    path("logout/", views.user_logout, name="user_logout"),
    path("change-email/", views.user_change_email, name="user_change_email"),
    path("reset-password/", views.reset_password, name="reset_password"),
    path("send/change-email/", views.send_change_email_mail, name="send_change"),
    path("verify/", views.VerifyEmail.as_view(), name="verify_email"),
    path("active/", views.ActivateUser.as_view(), name="activate_user"),
    # 소셜 회원가입, 로그인
    path("kakao/login/", views.KakaoLoginAPIView.as_view(), name="kakao_login"),
    path("kakao/login/callback/", views.kakao_callback, name="kakao_callback"),
    path("google/login/", views.GoogleLoginAPIView.as_view(), name="google_login"),
    path("google/login/callback/", views.google_callback, name="google_callback"),
]
