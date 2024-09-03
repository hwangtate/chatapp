from django.contrib.auth import login, logout
from django.core import signing
from django.core.signing import TimestampSigner, SignatureExpired

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from accounts.models import CustomUser
from .serializers import (
    UserSerializer,
    UserRegisterSerializer,
    UserLoginSerializer,
    UserChangeEmailSerializer,
    UserResetPasswordSerializer,
)
from .mail import EmailService


@api_view(["GET", "PUT", "DELETE"])
@permission_classes([IsAuthenticated])
def user_profile(request):
    user = request.user

    if request.method == "GET":
        serializer = UserSerializer(user)
        return Response(serializer.data)

    if request.method == "PUT":
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == "DELETE":
        logout(request)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(["POST"])
@permission_classes([AllowAny])
def user_register(request):
    serializer = UserRegisterSerializer(data=request.data)

    if serializer.is_valid():
        user = serializer.save()

        email_service = EmailService(user, request)
        email_service.send_activation_mail()

        data = {
            "success": True,
            "email": serializer.data["email"],
            "username": serializer.data["username"],
        }

        return Response(data, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
@permission_classes([AllowAny])
def activate_user(request):
    code = request.GET.get("code", "")
    signer = TimestampSigner()

    try:
        decoded_user_email = signing.loads(code)
        email = signer.unsign(decoded_user_email, max_age=60 * 3)
        user = CustomUser.objects.get(email=email)
    except (TypeError, SignatureExpired):
        return Response({"error": "expired time"}, status=status.HTTP_400_BAD_REQUEST)

    user.is_active = True
    user.email_is_verified = True
    user.save()
    return Response(
        {"message": "Account activated successfully."}, status=status.HTTP_200_OK
    )


@api_view(["POST"])
@permission_classes([AllowAny])
def user_login(request):
    serializer = UserLoginSerializer(data=request.data)

    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    user = CustomUser.objects.get(email=serializer.data["email"])

    login(request, user)

    data = {
        "success": True,
        "email": serializer.data["email"],
        "username": user.username,
    }

    return Response(data, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def user_logout(request):
    logout(request)

    data = {
        "success": True,
    }

    return Response(data, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def user_change_email(request):
    serializer = UserChangeEmailSerializer(
        data=request.data, context={"request": request}
    )

    if serializer.is_valid():
        user = CustomUser.objects.get(email=request.user.email)
        user = serializer.update(user, serializer.validated_data)

        email_service = EmailService(user, request)
        email_service.send_change_email_mail()

        return Response(
            {
                "success": True,
                "email": serializer.data["new_email"],
            }
        )

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
@permission_classes([AllowAny])
def verify_email(request):
    code = request.GET.get("code", "")
    signer = TimestampSigner()

    try:
        decoded_user_email = signing.loads(code)
        email = signer.unsign(decoded_user_email, max_age=60 * 3)
        user = CustomUser.objects.get(email=email)
    except (TypeError, SignatureExpired):
        return Response({"error": "expired time"}, status=status.HTTP_400_BAD_REQUEST)

    user.email_is_verified = True
    user.save()
    return Response(
        {"message": "Email confirmed successfully."}, status=status.HTTP_200_OK
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def reset_password(request):
    serializer = UserResetPasswordSerializer(
        data=request.data, context={"request": request}
    )

    if serializer.is_valid():
        user = request.user
        user = serializer.update(user, serializer.validated_data)
        user.save()

        return Response(
            {"message": "Password reset successfully."}, status=status.HTTP_200_OK
        )

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
