from .base import *

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(os.path.join(BASE_DIR, ".env"))

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": os.getenv("DATABASE_NAME"),
        "USER": os.getenv("DATABASE_USER"),
        "PASSWORD": os.getenv("DATABASE_PASSWORD"),
        "HOST": os.getenv("DATABASE_HOST"),
        "PORT": os.getenv("DATABASE_PORT"),
    }
}

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_USE_TLS = True
EMAIL_PORT = 587
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")

KAKAO_CONFIG = {
    # key
    "REST_API_KEY": os.getenv("KAKAO_REST_API_KEY"),
    "CLIENT_SECRET_KEY": os.getenv("KAKAO_CLIENT_SECRET_KEY"),
    # uri
    "LOGIN_URI": "https://kauth.kakao.com/oauth/authorize",
    "TOKEN_URI": "https://kauth.kakao.com/oauth/token",
    "PROFILE_URI": "https://kapi.kakao.com/v2/user/me",
    "REDIRECT_URIS": "http://127.0.0.1:8000/account/kakao/login/callback/",
    # type
    "GRANT_TYPE": "authorization_code",
    "CONTENT_TYPE": "application/x-www-form-urlencoded;charset=utf-8",
}

GOOGLE_CONFIG = {
    # key
    "CLIENT_ID": os.getenv("GOOGLE_CLIENT_ID"),
    "CLIENT_SECRET": os.getenv("GOOGLE_CLIENT_SECRET"),
    # uri
    "PROFILE_URI": "https://www.googleapis.com/oauth2/v3/userinfo",
    "LOGIN_URI": "https://accounts.google.com/o/oauth2/v2/auth",
    "TOKEN_URI": "https://oauth2.googleapis.com/token",
    "REDIRECT_URIS": "http://127.0.0.1:8000/account/google/login/callback/",
    "SCOPE": "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile",
    # type
    "GRANT_TYPE": "authorization_code",
    "CONTENT_TYPE": "application/x-www-form-urlencoded",
    # host
    "HOST": "oauth2.googleapis.com",
}

NAVER_CONFIG = {
    # key
    "CLIENT_ID": os.getenv("NAVER_CLIENT_ID"),
    "CLIENT_SECRET": os.getenv("NAVER_CLIENT_SECRET"),
    # uri
    "LOGIN_URI": "https://nid.naver.com/oauth2.0/authorize",
    "TOKEN_URI": "https://nid.naver.com/oauth2.0/token",
    "PROFILE_URI": "https://openapi.naver.com/v1/nid/me",
    "REDIRECT_URIS": "http://127.0.0.1:8000/account/naver/login/callback/",
    # type
    "GRANT_TYPE": "authorization_code",
    "CONTENT_TYPE": "application/x-www-form-urlencoded",
}
