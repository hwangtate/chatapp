from django.contrib.auth import authenticate, login
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import ValidationError, ParseError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.authtoken.models import Token

from accounts.models import CustomUser
from .serializers import UserSerializer, UserRegisterSerializer
from .permissions import IsAdminUser


@api_view(["GET"])
@permission_classes([IsAdminUser])
def user_list(request):

    if request.method == "GET":
        user = CustomUser.objects.all()
        serializer = UserSerializer(user, many=True)
        return Response(serializer.data)


@api_view(["GET"])
@permission_classes([IsAdminUser])
def user_detail(request, pk):
    if request.method == "GET":
        user = CustomUser.objects.get(pk=pk)
        serializer = UserSerializer(user)
        return Response(serializer.data)


@api_view(["POST"])
@permission_classes([AllowAny])
def user_register(request):
    if request.method == "POST":
        serializer = UserRegisterSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
