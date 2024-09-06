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
    CommonDecodeSignerUser,
    SocialLogin,
    SocialLoginCallback,
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
class VerifyEmail(CommonDecodeSignerUser, APIView):

    permission_classes = (AllowAny,)

    def get(self, request):
        return self.decode_signer(request)

    def handle_save_user(self, request):
        self.user.email_is_verified = True
        self.user.save()

        return Response({"message": "Email confirmed successfully."}, status=status.HTTP_200_OK)


# permission_classes = (AllowAny,)
class ActivateUser(CommonDecodeSignerUser, APIView):

    permission_classes = (AllowAny,)

    def get(self, request):
        return self.decode_signer(request)

    def handle_save_user(self, request):
        self.user.is_active = True
        self.user.email_is_verified = True
        self.user.save()

        return Response({"message": "Account activated successfully."}, status=status.HTTP_200_OK)


"""Social Account API"""


# permission_classes = (AllowAny, IsLoggedIn)
class KakaoLogin(SocialLogin, APIView):

    permission_classes = (AllowAny, IsLoggedIn)

    def get(self, request):
        return redirect(self.social_login(kakao=True))

    def get_social_provider_data(self):
        client_id = KAKAO_CONFIG["REST_API_KEY"]
        redirect_uri = KAKAO_CONFIG["REDIRECT_URIS"]
        login_uri = KAKAO_CONFIG["LOGIN_URI"]

        return client_id, redirect_uri, login_uri


# permission_classes = (AllowAny, IsLoggedIn)
class GoogleLogin(SocialLogin, APIView):

    permission_classes = (AllowAny, IsLoggedIn)

    def get(self, request):
        return redirect(self.social_login(google=True))

    def get_social_provider_data(self):
        client_id = GOOGLE_CONFIG["CLIENT_ID"]
        redirect_uri = GOOGLE_CONFIG["REDIRECT_URIS"]
        login_uri = GOOGLE_CONFIG["LOGIN_URI"]

        return client_id, redirect_uri, login_uri


# permission_classes = (AllowAny, IsLoggedIn)
class NaverLogin(SocialLogin, APIView):

    permission_classes = (AllowAny, IsLoggedIn)

    def get(self, request):
        return redirect(self.social_login(naver=True))

    def get_social_provider_data(self):
        client_id = NAVER_CONFIG["CLIENT_ID"]
        redirect_uri = NAVER_CONFIG["REDIRECT_URIS"]
        login_uri = NAVER_CONFIG["LOGIN_URI"]

        return client_id, redirect_uri, login_uri


# permission_classes = (AllowAny, IsLoggedIn)
class KakaoLoginCallback(SocialLoginCallback):

    permission_classes = (AllowAny, IsLoggedIn)

    def get(self, request):
        self.token_request_data = self.get_social_provider_data(request)
        self.profile_uri = KAKAO_CONFIG["PROFILE_URI"]
        self.token_uri = KAKAO_CONFIG["TOKEN_URI"]
        self.code = request.query_params.get("code")
        self.state = request.query_params.get("state")

        user_info_json = self.get_user_info_json()

        kakao_account = user_info_json.get("kakao_account")
        profile = kakao_account.get("profile")

        user_data = {"email": kakao_account.get("email"), "username": profile.get("nickname"), "social_type": "kakao"}

        return self.social_login_or_register(request, data=user_data)

    def get_social_provider_data(self, request):
        provider_data = {
            "grant_type": KAKAO_CONFIG["GRANT_TYPE"],
            "client_id": KAKAO_CONFIG["REST_API_KEY"],
            "client_secret": KAKAO_CONFIG["CLIENT_SECRET_KEY"],
            "redirect_uri": KAKAO_CONFIG["REDIRECT_URIS"],
        }
        return provider_data


# permission_classes = (AllowAny, IsLoggedIn)
class GoogleLoginCallback(SocialLoginCallback, APIView):

    permission_classes = (AllowAny, IsLoggedIn)

    def get(self, request):
        user_info_json = self.get_user_info_json(request)

        email = user_info_json.get("email")
        username = user_info_json.get("name")
        social_type = "google"

        data = self.get_user_data(email=email, username=username, social_type=social_type)

        return social_login_or_register(
            request,
            data=data,
            email=email,
            social_type=social_type,
            response=data,
        )

    def get_social_provider_data(self, request):
        token_request_data = {
            "grant_type": GOOGLE_CONFIG["GRANT_TYPE"],
            "client_id": GOOGLE_CONFIG["CLIENT_ID"],
            "client_secret": GOOGLE_CONFIG["CLIENT_SECRET"],
            "redirect_uri": GOOGLE_CONFIG["REDIRECT_URIS"],
            "code": self.get_code(request),
        }

        token_headers = {
            "Content-type": GOOGLE_CONFIG["CONTENT_TYPE"],
            "host": GOOGLE_CONFIG["HOST"],
        }

        social_uri = {
            "token_uri": GOOGLE_CONFIG["TOKEN_URI"],
            "profile_uri": GOOGLE_CONFIG["PROFILE_URI"],
        }

        return token_request_data, token_headers, social_uri


# permission_classes = (AllowAny, IsLoggedIn)
class NaverLoginCallback(SocialLoginCallback, APIView):

    permission_classes = (AllowAny, IsLoggedIn)

    def get(self, request):
        user_info_json = self.get_user_info_json(request)

        naver_response = user_info_json.get("response")
        email = naver_response.get("email")
        username = naver_response.get("name")
        social_type = "naver"

        data = self.get_user_data(email=email, username=username, social_type=social_type)

        return social_login_or_register(
            request,
            data=data,
            email=email,
            social_type=social_type,
            response=data,
        )

    def get_social_provider_data(self, request):
        token_request_data = {
            "grant_type": NAVER_CONFIG["GRANT_TYPE"],
            "client_id": NAVER_CONFIG["CLIENT_ID"],
            "client_secret": NAVER_CONFIG["CLIENT_SECRET"],
            "redirect_uri": NAVER_CONFIG["REDIRECT_URIS"],
            "code": self.get_code(request),
        }

        token_headers = {
            "Content-type": NAVER_CONFIG["CONTENT_TYPE"],
            "state": self.get_state(request),
        }

        social_uri = {
            "token_uri": NAVER_CONFIG["TOKEN_URI"],
            "profile_uri": NAVER_CONFIG["PROFILE_URI"],
        }

        return token_request_data, token_headers, social_uri
