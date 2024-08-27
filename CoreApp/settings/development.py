from .base import *  # noqa

import os
from pathlib import Path
from dotenv import load_dotenv

# BASE_DIR 정의
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# .env 파일 로드
load_dotenv(os.path.join(BASE_DIR, ".env"))

# DATABASE 설정
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

# DEBUG 설정
DEBUG = os.getenv("DEBUG", "True") == "True"
