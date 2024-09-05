from django.contrib.auth import login, logout
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
)
from accounts.mail import EmailService
from accounts.permissions import IsEmailVerified, IsCommonUser, IsLoggedIn
from accounts.services import (
    social_login_or_register,
    CommonDecodeSignerUser,
    SocialLoginAPIView,
    SocialCallback,
)
from coreapp.settings.development import KAKAO_CONFIG, GOOGLE_CONFIG, NAVER_CONFIG


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


"""Social Account API"""


# permission_classes = (AllowAny, IsLoggedIn)
class KakaoLoginAPIView(SocialLoginAPIView):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.client_id = KAKAO_CONFIG["REST_API_KEY"]
        self.redirect_uri = KAKAO_CONFIG["REDIRECT_URIS"]
        self.login_uri = KAKAO_CONFIG["LOGIN_URI"]

    def get(self, request, *args, **kwargs):
        return redirect(self.social_login(kakao=True))


# permission_classes = (AllowAny, IsLoggedIn)
class GoogleLoginAPIView(SocialLoginAPIView):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.client_id = GOOGLE_CONFIG["CLIENT_ID"]
        self.redirect_uri = GOOGLE_CONFIG["REDIRECT_URIS"]
        self.login_uri = GOOGLE_CONFIG["LOGIN_URI"]

    def get(self, request, *args, **kwargs):
        return redirect(self.social_login(google=True))


# permission_classes = (AllowAny, IsLoggedIn)
class NaverLoginAPIView(SocialLoginAPIView):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.client_id = NAVER_CONFIG["CLIENT_ID"]
        self.redirect_uri = NAVER_CONFIG["REDIRECT_URIS"]
        self.login_uri = NAVER_CONFIG["LOGIN_URI"]

    def get(self, request, *args, **kwargs):
        return redirect(self.social_login(naver=True))


# permission_classes = (AllowAny, IsLoggedIn)
class KakaoLoginCallback(SocialCallback, APIView):

    permission_classes = (AllowAny, IsLoggedIn)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.client_id = KAKAO_CONFIG["REST_API_KEY"]
        self.client_secret = KAKAO_CONFIG["CLIENT_SECRET_KEY"]

        self.redirect_uri = KAKAO_CONFIG["REDIRECT_URIS"]
        self.token_uri = KAKAO_CONFIG["TOKEN_URI"]
        self.profile_uri = KAKAO_CONFIG["PROFILE_URI"]

        self.code = None
        self.grant_type = KAKAO_CONFIG["GRANT_TYPE"]
        self.content_type = KAKAO_CONFIG["CONTENT_TYPE"]

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


# permission_classes = (AllowAny, IsLoggedIn)
class GoogleLoginCallback(SocialCallback, APIView):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.client_id = GOOGLE_CONFIG["CLIENT_ID"]
        self.client_secret = GOOGLE_CONFIG["CLIENT_SECRET"]

        self.redirect_uri = GOOGLE_CONFIG["REDIRECT_URIS"]
        self.token_uri = GOOGLE_CONFIG["TOKEN_URI"]
        self.profile_uri = GOOGLE_CONFIG["PROFILE_URI"]

        self.code = None
        self.grant_type = GOOGLE_CONFIG["GRANT_TYPE"]
        self.content_type = GOOGLE_CONFIG["CONTENT_TYPE"]
        self.host = GOOGLE_CONFIG["HOST"]

    def get(self, request, *args, **kwargs):
        self.code = self.get_code(request)
        user_info_json = self.get_user_info_json(host=self.host)

        email = user_info_json.get("email")
        username = user_info_json.get("name")
        social_type = "google"

        data = self.user_data(email=email, username=username, social_type=social_type)

        return social_login_or_register(
            request,
            data=data,
            email=email,
            social_type=social_type,
            response=data,
        )


# permission_classes = (AllowAny, IsLoggedIn)
class NaverLoginCallback(SocialCallback, APIView):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.client_id = NAVER_CONFIG["CLIENT_ID"]
        self.client_secret = NAVER_CONFIG["CLIENT_SECRET"]

        self.redirect_uri = NAVER_CONFIG["REDIRECT_URIS"]
        self.token_uri = NAVER_CONFIG["TOKEN_URI"]
        self.profile_uri = NAVER_CONFIG["PROFILE_URI"]

        self.code = None
        self.grant_type = NAVER_CONFIG["GRANT_TYPE"]
        self.content_type = NAVER_CONFIG["CONTENT_TYPE"]
        self.state = None

    def get(self, request, *args, **kwargs):
        self.code = self.get_code(request)
        self.state = self.get_state(request)

        user_info_json = self.get_user_info_json(state=self.state)

        naver_response = user_info_json.get("response")
        email = naver_response.get("email")
        username = naver_response.get("name")
        social_type = "naver"

        data = self.user_data(email=email, username=username, social_type=social_type)

        return social_login_or_register(
            request,
            data=data,
            email=email,
            social_type=social_type,
            response=data,
        )
