from abc import abstractmethod

from django.contrib.auth import login, logout
from django.core import signing
from django.core.signing import TimestampSigner, SignatureExpired

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import CustomUser
from .serializers import (
    UserSerializer,
    UserRegisterSerializer,
    UserLoginSerializer,
    UserChangeEmailSerializer,
    UserResetPasswordSerializer,
)
from .mail import EmailService
from .permissions import IsEmailVerified


@api_view(["GET", "PUT", "DELETE"])
@permission_classes([IsAuthenticated, IsEmailVerified])
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
        email_service.send_register_mail()

        data = {
            "success": True,
            "email": serializer.data["email"],
            "username": serializer.data["username"],
        }

        return Response(data, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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
@permission_classes([IsAuthenticated, IsEmailVerified])
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


@api_view(["POST"])
@permission_classes([IsAuthenticated, IsEmailVerified])
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


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def send_change_email_mail(request):
    try:
        user = CustomUser.objects.get(email=request.user.email)
        email_service = EmailService(user, request)
        email_service.send_change_email_mail()
        return Response({"success": True}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def send_register_mail(request):
    try:
        user = CustomUser.objects.get(email=request.user.email)
        email_service = EmailService(user, request)
        email_service.send_register_mail()
        return Response({"success": True}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# permission_classes : AllowAny
class CommonDecodeSignerUser(APIView):
    """
    GET 요청에서 서명된 사용자 이메일 토큰을 디코딩하고 검증하는
    공통 기능을 처리하는 기본 클래스.

    이 클래스는 서브클래스에서 확장하여 사용자가 서명된 토큰을
    디코딩하고, 사용자의 이메일을 검증하며, 특정 작업(예: 계정 활성화,
    이메일 주소 확인)을 수행할 때 사용됩니다.

    Attributes:
        code (str): GET 요청에서 추출된 서명된 토큰.
        signer (TimestampSigner): 토큰을 검증하는 데 사용되는 서명자.
        user (CustomUser): 검증된 이메일과 연결된 사용자 인스턴스.

    Methods:
        get(request, *args, **kwargs):
            GET 요청을 처리하고, 서명된 토큰을 디코딩 및 검증하여
            연결된 사용자를 검색한 후, 서브클래스에서 정의된 `handle_save_user`
            메서드를 호출하여 추가 작업을 수행합니다.

        handle_save_user(request, *args, **kwargs):
            서브클래스에서 구현해야 하는 추상 메서드입니다. 사용자가
            성공적으로 검색된 후 추가 작업(예: 계정 활성화 또는 이메일
            확인)을 수행하는 데 사용됩니다.
    """

    permission_classes = (AllowAny,)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.code = None
        self.signer = None
        self.user = None

    def get(self, request, *args, **kwargs):
        self.code = request.GET.get("code", "")
        self.signer = TimestampSigner()
        try:
            decoded_user_email = signing.loads(self.code)
            email = self.signer.unsign(decoded_user_email, max_age=60 * 3)
            self.user = CustomUser.objects.get(email=email)

        except SignatureExpired:
            return Response(
                {"error": "expired time"}, status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return self.handle_save_user(request)

    @abstractmethod
    def handle_save_user(self, request, *args, **kwargs):
        pass


class VerifyEmail(CommonDecodeSignerUser):
    def handle_save_user(self, request, *args, **kwargs):
        self.user.email_is_verified = True
        self.user.save()
        return Response(
            {"message": "Email confirmed successfully."}, status=status.HTTP_200_OK
        )


class ActivateUser(CommonDecodeSignerUser):

    def handle_save_user(self, request, *args, **kwargs):
        self.user.is_active = True
        self.user.email_is_verified = True
        self.user.save()
        return Response(
            {"message": "Account activated successfully."}, status=status.HTTP_200_OK
        )
