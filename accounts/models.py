from django.contrib.auth.models import AbstractUser, PermissionsMixin
from django.db import models

from .manager import CustomUserManager


class CustomUser(AbstractUser, PermissionsMixin):
    class SocialChoices(models.TextChoices):
        COMMON = "common", "Common"
        KAKAO = "kakao", "Kakao"
        NAVER = "naver", "Naver"
        GOOGLE = "google", "Google"

    email = models.EmailField(unique=True)
    username = models.CharField(
        max_length=50, blank=True, unique=False, default="anonym"
    )
    social_type = models.CharField(
        max_length=20,
        choices=SocialChoices.choices,
        default=SocialChoices.COMMON,
    )

    email_is_verified = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)

    EMAIL_FIELD = "email"
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def save(self, *args, **kwargs):
        self.email = self.email.lower()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.email
