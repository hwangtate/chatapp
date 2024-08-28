from rest_framework.authtoken.models import Token
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from .models import CustomUser

import re


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        exclude = ["password", "first_name", "last_name"]


class UserRegisterSerializer(serializers.ModelSerializer):
    username = serializers.CharField()
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ("username", "email", "password", "password2")
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

    def validate(self, instance):
        password = instance["password"]
        password2 = instance["password2"]

        if len(password) < 7:
            raise ValidationError("Password must be at least 8 characters")

        if not re.search(r"[A-Z]", password):
            raise ValidationError(
                "Password must contain at least one uppercase letter."
            )

        if not re.search(r"[a-z]", password):
            raise ValidationError(
                "Password must contain at least one lowercase letter."
            )

        if not re.search(r"[0-9]", password):
            raise ValidationError("Password must contain at least one number")

        if not re.search(r"[!@#$%^*+=-]", password):
            raise ValidationError(
                {"password": "Password must contain at least one special character."}
            )

        if password != password2:
            raise ValidationError({"message": "Both password must match"})

        if CustomUser.objects.filter(email=instance["email"]).exists():
            raise ValidationError({"message": "Email already taken!"})

        return instance

    def create(self, validated_data):
        password = validated_data.pop("password")
        password2 = validated_data.pop("password2")
        user = CustomUser.objects.create(**validated_data)
        user.set_password(password)
        user.save()
        return user


class UserLoginSerializer(serializers.Serializer):

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ("email", "password")

    def validate(self, instance):
        self.email = instance["email"]
        self.password = instance["password"]

        try:
            self.user = CustomUser.objects.get(email=self.email)

        except CustomUser.DoesNotExist:
            raise ValidationError({"message": "Email doesn't exist!"})

        if not self.user.check_password(self.password):
            raise ValidationError({"message": "Invalid password"})

        return instance
