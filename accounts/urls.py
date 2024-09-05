from django.urls import path
from . import views

urlpatterns = [
    # 계정 정보
    path("profile/", views.user_profile, name="user_profile"),
    # 일반 회원가입, 로그인, 로그아웃
    path("register/", views.user_register, name="user_register"),
    path("login/", views.user_login, name="user_login"),
    path("logout/", views.user_logout, name="user_logout"),
    # 이메일 변경, 비밀번호 변경
    path("change-email/", views.user_change_email, name="user_change_email"),
    path("reset-password/", views.reset_password, name="reset_password"),
    # 이메일 변경 메일 재전송 path
    path("send/change-email/", views.send_change_email_mail, name="send_change"),
    # 이메일 인증, 이메일 인증 및 계정 활성화
    path("verify/", views.VerifyEmail.as_view(), name="verify_email"),
    path("active/", views.ActivateUser.as_view(), name="activate_user"),
    # 소셜 회원가입, 로그인
    path("kakao/login/", views.KakaoLogin.as_view(), name="kakao_login"),
    path("kakao/login/callback/", views.KakaoLoginLoginCallback.as_view(), name="kakao_callback"),
    path("google/login/", views.GoogleLogin.as_view(), name="google_login"),
    path("google/login/callback/", views.GoogleLoginLoginCallback.as_view(), name="google_callback"),
    path("naver/login/", views.NaverLogin.as_view(), name="naver_login"),
    path("naver/login/callback/", views.NaverLoginLoginCallback.as_view(), name="naver_callback"),
]
