from django.contrib import admin
from .models import CustomUser


@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ("username", "email", "social_type")
    list_filter = ("social_type", "is_active", "email_is_verified", "is_superuser")
    search_fields = ("username", "email")
    exclude = ("password",)
