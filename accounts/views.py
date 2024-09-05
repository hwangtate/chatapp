import requests

from django.contrib.auth import login, logout

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from accounts.models import CustomUser
from accounts.serializers import (
    UserSerializer,
    UserRegisterSerializer,
    UserLoginSerializer,
    UserChangeEmailSerializer,
    UserResetPasswordSerializer,
)
from accounts.mail import EmailService
from accounts.permissions import IsEmailVerified, IsCommonUser, IsLoggedIn
from accounts.services import (
    social_login_or_register,
    CommonDecodeSignerUser,
    SocialLoginAPIView,
    SocialCallbackAPIView,
)
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
@permission_classes([AllowAny, IsLoggedIn])
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
@permission_classes([AllowAny, IsLoggedIn])
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
    serializer = UserChangeEmailSerializer(data=request.data, context={"request": request})

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
    serializer = UserResetPasswordSerializer(data=request.data, context={"request": request})

    if serializer.is_valid():
        user = request.user
        user = serializer.update(user, serializer.validated_data)
        user.save()

        return Response({"message": "Password reset successfully."}, status=status.HTTP_200_OK)

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


# permission_classes = (AllowAny,)
class VerifyEmail(CommonDecodeSignerUser):

    def get(self, request, *args, **kwargs):
        return self.decode_signer(request)

    def handle_save_user(self, request, *args, **kwargs):
        self.user.email_is_verified = True
        self.user.save()

        return Response({"message": "Email confirmed successfully."}, status=status.HTTP_200_OK)


# permission_classes = (AllowAny,)
class ActivateUser(CommonDecodeSignerUser):

    def get(self, request, *args, **kwargs):
        return self.decode_signer(request)

    def handle_save_user(self, request, *args, **kwargs):
        self.user.is_active = True
        self.user.email_is_verified = True
        self.user.save()

        return Response({"message": "Account activated successfully."}, status=status.HTTP_200_OK)


# permission_classes = (AllowAny, IsLoggedIn)
class KakaoLoginAPIView(SocialLoginAPIView):

    def get(self, request, *args, **kwargs):
        return self.kakao_login()


# permission_classes = (AllowAny, IsLoggedIn)
class GoogleLoginAPIView(SocialLoginAPIView):

    def get(self, request, *args, **kwargs):
        return self.google_login()


class KakaoLoginCallbackAPIView(SocialCallbackAPIView):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.grant_type = "authorization_code"
        self.client_id = (KAKAO_KEY_CONFIG["KAKAO_REST_API_KEY"],)
        self.client_secret = KAKAO_KEY_CONFIG["KAKAO_CLIENT_SECRET_KEY"]
        self.redirect_uri = KAKAO_URI_CONFIG["KAKAO_REDIRECT_URI"]
        self.code = None
        self.content_type = "application/x-www-form-urlencoded;charset=utf-8"

        self.token_uri = KAKAO_URI_CONFIG["KAKAO_TOKEN_URI"]
        self.profile_uri = KAKAO_URI_CONFIG["KAKAO_PROFILE_URI"]

    def get(self, request, *args, **kwargs):
        self.code = self.get_code(request)
        user_info_json = self.get_user_info_json()

        kakao_account = user_info_json.get("kakao_account")
        profile = kakao_account.get("profile")

        email = kakao_account.get("email")
        username = profile.get("nickname")
        social_type = "kakao"

        data = self.user_data(email=email, username=username, social_type=social_type)

        return social_login_or_register(
            request,
            data=data,
            email=email,
            social_type=social_type,
            response=data,
        )

    def get_user_info_json(self, **kwargs):
        token_request_data, token_headers = self.token_data(
            grant_type=self.grant_type,
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=self.redirect_uri,
            code=self.code,
            content_type=self.content_type,
        )

        token_response = self.requests_post_token(
            token_uri=self.token_uri,
            token_request_data=token_request_data,
            token_headers=token_headers,
        )

        auth_headers = self.transfer_token(
            token_response=token_response,
        )

        user_info_response = self.requests_get_user(
            profile_uri=self.profile_uri,
            auth_headers=auth_headers,
        )

        user_info_json = self.user_info_json(
            user_info_response=user_info_response,
        )

        return user_info_json


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
