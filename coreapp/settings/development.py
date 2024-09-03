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

KAKAO_KEY_CONFIG = {
    "KAKAO_REST_API_KEY": os.getenv("KAKAO_REST_API_KEY"),
    "KAKAO_CLIENT_SECRET_KEY": os.getenv("KAKAO_CLIENT_SECRET_KEY"),
}

KAKAO_URI_CONFIG = {
    "KAKAO_LOGIN_URI": "https://kauth.kakao.com/oauth/authorize",
    "KAKAO_TOKEN_URI": "https://kauth.kakao.com/oauth/token",
    "KAKAO_PROFILE_URI": "https://kapi.kakao.com/v2/user/me",
    "KAKAO_REDIRECT_URI": "http://127.0.0.1:8000/account/kakao/login/callback/",
}
