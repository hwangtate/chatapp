from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from .models import CustomUser

import re


class UserSerializer(serializers.ModelSerializer):
    last_login = serializers.DateTimeField(format="%Y-%m-%d %H:%M", read_only=True)
    date_joined = serializers.DateTimeField(format="%Y-%m-%d %H:%M", read_only=True)

    class Meta:
        model = CustomUser
        exclude = ["password"]


class UserRegisterSerializer(serializers.ModelSerializer):
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

    def validate(self, data):
        password = data["password"]
        password2 = data["password2"]

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

        if re.search(r"(.)\1\1", password):
            raise ValidationError(
                "Password must not contain three consecutive identical characters."
            )

        if password != password2:
            raise ValidationError({"message": "Both password must match"})

        if CustomUser.objects.filter(email=data["email"]).exists():
            raise ValidationError({"message": "Email already taken!"})

        return data

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

    def validate(self, data):
        email = data["email"]
        password = data["password"]

        try:
            user = CustomUser.objects.get(email=email)

        except CustomUser.DoesNotExist:
            raise ValidationError({"message": "Email doesn't exist!"})

        if not user.is_active:
            raise ValidationError({"message": "User is not active!"})

        if not user.check_password(password):
            raise ValidationError({"message": "Invalid password"})

        return data


class UserChangeEmailSerializer(serializers.Serializer):
    pass


class UserFindPasswordSerializer(serializers.Serializer):
    pass


class UserResetPasswordSerializer(serializers.Serializer):
    pass
