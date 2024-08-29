from django.contrib.auth import login, logout
from django.utils.http import urlsafe_base64_decode

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from accounts.models import CustomUser
from .serializers import UserSerializer, UserRegisterSerializer, UserLoginSerializer
from .permissions import IsAdminUser
from .tokens import account_activation_token
from .mail import send_activation_email


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


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_profile(request):
    user = request.user
    serializer = UserSerializer(user)
    return Response(serializer.data)


@api_view(["POST"])
@permission_classes([AllowAny])
def user_register(request):
    serializer = UserRegisterSerializer(data=request.data)

    if serializer.is_valid():
        user = serializer.save()

        send_activation_email(user, request)

        response = {
            "success": True,
            "email": serializer.data["email"],
            "username": serializer.data["username"],
        }

        return Response(response, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
@permission_classes([AllowAny])
def activate(request, uidb64, token):
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
        return Response(
            {"error": "Activation link is invalid!"}, status=status.HTTP_400_BAD_REQUEST
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

    response = {
        "success": True,
    }

    return Response(response, status=status.HTTP_200_OK)
