from django.contrib.auth import login, logout
from rest_framework import status, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from accounts.models import CustomUser
from .serializers import UserSerializer, UserRegisterSerializer, UserLoginSerializer
from .permissions import IsAdminUser


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
        serializer.save()
        response = {
            "success": True,
            "user": serializer.data,
        }
        return Response(response, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([AllowAny])
def user_login(request):
    serializer = UserLoginSerializer(data=request.data)

    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    login(request, CustomUser.objects.get(email=serializer.data["email"]))

    data = {
        "success": True,
        "email": serializer.data["email"],
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
