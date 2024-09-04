from abc import abstractmethod
import requests

from django.contrib.auth import login, logout
from django.core import signing
from django.core.signing import TimestampSigner, SignatureExpired
from django.shortcuts import redirect

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import CustomUser
from accounts.serializers import (
    UserSerializer,
    UserRegisterSerializer,
    UserLoginSerializer,
    UserChangeEmailSerializer,
    UserResetPasswordSerializer,
    SocialRegisterSerializer,
)
from accounts.mail import EmailService
from accounts.permissions import IsEmailVerified, IsCommonUser
from coreapp.settings.development import (
    KAKAO_KEY_CONFIG,
    KAKAO_URI_CONFIG,
    GOOGLE_CONFIG,
)


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
@permission_classes([IsAuthenticated, IsEmailVerified, IsCommonUser])
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
@permission_classes([IsAuthenticated, IsEmailVerified, IsCommonUser])
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
@permission_classes([IsAuthenticated, IsEmailVerified, IsCommonUser])
def send_change_email_mail(request):
    try:
        user = CustomUser.objects.get(email=request.user.email)
        email_service = EmailService(user, request)
        email_service.send_change_email_mail()
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


"""Social Login And Register Function"""


def social_login_or_register(request, data, email, social_type, response):

    if CustomUser.objects.filter(email=email, social_type=social_type).exists():
        user = CustomUser.objects.get(email=email)
        login(request, user)

        return Response(response, status=status.HTTP_200_OK)

    serializer = SocialRegisterSerializer(data=data)

    if serializer.is_valid():
        user = serializer.save()
        login(request, user)

        return Response(response, status=status.HTTP_200_OK)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


"""Kakao Login API"""


@api_view(["GET"])
@permission_classes([AllowAny])
def kakao_login(request):
    client_id = KAKAO_KEY_CONFIG["KAKAO_REST_API_KEY"]
    redirect_uri = KAKAO_URI_CONFIG["KAKAO_REDIRECT_URI"]
    kakao_login_uri = KAKAO_URI_CONFIG["KAKAO_LOGIN_URI"]

    url = f"{kakao_login_uri}?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code"

    return redirect(url)


@api_view(["GET"])
@permission_classes([AllowAny])
def kakao_callback(request):
    code = request.query_params.get("code")

    if not code:
        return Response({"error": "Code Not Found"}, status=status.HTTP_400_BAD_REQUEST)

    token_request_data = {
        "grant_type": "authorization_code",
        "client_id": KAKAO_KEY_CONFIG["KAKAO_REST_API_KEY"],
        "redirect_uri": KAKAO_URI_CONFIG["KAKAO_REDIRECT_URI"],
        "code": code,
        "client_secret": KAKAO_KEY_CONFIG["KAKAO_CLIENT_SECRET_KEY"],
    }
    token_headers = {"Content-type": "application/x-www-form-urlencoded;charset=utf-8"}

    try:
        token_response = requests.post(
            KAKAO_URI_CONFIG["KAKAO_TOKEN_URI"],
            data=token_request_data,
            headers=token_headers,
        )
    except Exception as e:
        return Response({"error token": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    token_json = token_response.json()
    access_token = token_json.get("access_token")
    access_token = f"Bearer {access_token}"
    auth_headers = {
        "Authorization": access_token,
    }

    try:
        user_info_response = requests.get(
            KAKAO_URI_CONFIG["KAKAO_PROFILE_URI"],
            headers=auth_headers,
        )
    except Exception as e:
        return Response({"error user_info": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    user_info_json = user_info_response.json()

    kakao_account = user_info_json.get("kakao_account")
    profile = kakao_account.get("profile")

    email = kakao_account.get("email")
    username = profile.get("nickname")
    social_type = "kakao"

    data = {
        "email": email,
        "username": username,
        "social_type": social_type,
    }

    response = {
        "social_type": social_type,
        "user_email": email,
        "username": username,
    }
    return social_login_or_register(
        request,
        data=data,
        email=email,
        social_type=social_type,
        response=response,
    )


"""Google Login API"""


@api_view(["GET"])
@permission_classes([AllowAny])
def google_login(request):
    client_id = GOOGLE_CONFIG["GOOGLE_CLIENT_ID"]
    redirect_uri = GOOGLE_CONFIG["GOOGLE_REDIRECT_URIS"]
    auth_uri = GOOGLE_CONFIG["GOOGLE_AUTH_URI"]
    scope = GOOGLE_CONFIG["GOOGLE_SCOPE"]

    url = f"{auth_uri}?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&scope={scope}"
    return redirect(url)


@api_view(["GET"])
@permission_classes([AllowAny])
def google_callback(request):
    code = request.query_params.get("code")

    if not code:
        return Response({"error": "Code Not Found"}, status=status.HTTP_400_BAD_REQUEST)

    token_request_data = {
        "grant_type": "authorization_code",
        "client_id": GOOGLE_CONFIG["GOOGLE_CLIENT_ID"],
        "client_secret": GOOGLE_CONFIG["GOOGLE_CLIENT_SECRET"],
        "code": code,
        "redirect_uri": GOOGLE_CONFIG["GOOGLE_REDIRECT_URIS"],
    }
    token_headers = {
        "Content-type": "application/x-www-form-urlencoded",
        "Host": "oauth2.googleapis.com",
    }

    try:
        token_response = requests.post(
            GOOGLE_CONFIG["GOOGLE_TOKEN_URI"],
            data=token_request_data,
            headers=token_headers,
        )
    except Exception as e:
        return Response({"error token": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    token_json = token_response.json()
    access_token = token_json.get("access_token")
    access_token = f"Bearer {access_token}"
    auth_headers = {
        "Authorization": access_token,
    }

    try:
        user_info_response = requests.get(
            GOOGLE_CONFIG["GOOGLE_PROFILE_URI"],
            headers=auth_headers,
        )
    except Exception as e:
        return Response({"error user_info": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    user_info_json = user_info_response.json()
    email = user_info_json.get("email")
    username = user_info_json.get("name")
    social_type = "google"

    data = {
        "email": email,
        "username": username,
        "social_type": social_type,
    }

    response = {
        "social_type": social_type,
        "user_email": email,
        "username": username,
    }

    return social_login_or_register(
        request,
        data=data,
        email=email,
        social_type=social_type,
        response=response,
    )
