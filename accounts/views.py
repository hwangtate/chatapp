from django.contrib.auth import login, logout
from django.utils.http import urlsafe_base64_decode

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
from .permissions import IsAdminUser
from .tokens import (
    account_activation_token,
    account_verification_token,
    account_reset_password_token,
)
from .mail import send_activation_mail, send_change_email_mail, send_reset_password_mail


@api_view(["GET"])
@permission_classes([IsAdminUser])
def user_list(request):
    user = CustomUser.objects.all()
    serializer = UserSerializer(user, many=True)
    return Response(serializer.data)


@api_view(["GET"])
@permission_classes([IsAdminUser])
def user_detail(request, pk):
    user = CustomUser.objects.get(pk=pk)
    serializer = UserSerializer(user)
    return Response(serializer.data)


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

        send_activation_mail(user, request)

        data = {
            "success": True,
            "email": serializer.data["email"],
            "username": serializer.data["username"],
        }

        return Response(data, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
@permission_classes([AllowAny])
def activate_user(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = CustomUser.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.email_is_verified = True
        user.save()
        return Response(
            {"message": "Account activated successfully."}, status=status.HTTP_200_OK
        )
    else:
        return Response({"error": "Errors..."}, status=status.HTTP_400_BAD_REQUEST)


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
    serializer = UserChangeEmailSerializer(data=request.data)

    if serializer.is_valid():
        user = CustomUser.objects.get(email=serializer.validated_data["old_email"])
        user = serializer.update(user, serializer.validated_data)

        send_change_email_mail(user, request)

        return Response(
            {
                "success": True,
                "email": serializer.data["new_email"],
            }
        )

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
@permission_classes([AllowAny])
def verify_email(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = CustomUser.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
        user = None

    if user is not None and account_verification_token.check_token(user, token):
        user.email_is_verified = True
        user.save()
        return Response(
            {"message": "Email confirmed successfully."}, status=status.HTTP_200_OK
        )
    else:
        return Response({"error": "Errors..."}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def send_mail_reset_password(request):
    try:
        user = request.user
    except CustomUser.DoesNotExist:
        return Response(
            {"error": "User not found."}, status=status.HTTP_400_BAD_REQUEST
        )

    send_reset_password_mail(user, request)

    return Response(
        {
            "success": True,
            "message": "Password reset email sent.",
        }
    )


@api_view(["GET", "POST"])
@permission_classes([AllowAny])
def reset_password(request, uidb64, token):
    if request.method == "GET":
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = CustomUser.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            return Response(
                {"error": "User not found."}, status=status.HTTP_400_BAD_REQUEST
            )

        if account_reset_password_token.check_token(user, token):
            return Response(
                {"message": "You can reset password"}, status=status.HTTP_200_OK
            )
        else:
            return Response(
                {"error": "You can't reset passoword"},
                status=status.HTTP_400_BAD_REQUEST,
            )

    if request.method == "POST":
        serializer = UserResetPasswordSerializer(request, data=request.data)

        if serializer.is_valid():
            user = request.user
            user = serializer.update(user, serializer.validated_data)
            user.save()

            return Response(
                {"message": "Password reset successfully."}, status=status.HTTP_200_OK
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
