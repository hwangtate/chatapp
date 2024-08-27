from django.contrib.auth import authenticate
from rest_framework import serializers
from .models import CustomUser


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        exclude = ["password", "first_name", "last_name"]


class UserRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ("username", "email", "password")
        read_only_fields = (
            "id",
            "is_active",
            "is_staff",
            "is_superuser",
            "first_name",
            "last_name",
            "last_login",
            "date_joined",
        )
