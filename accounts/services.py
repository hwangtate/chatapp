from abc import abstractmethod

import requests
from django.contrib.auth import login
from django.core import signing
from django.core.signing import TimestampSigner, SignatureExpired

from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import CustomUser
from accounts.permissions import IsLoggedIn
from accounts.serializers import SocialRegisterSerializer
from coreapp.settings.development import KAKAO_CONFIG, GOOGLE_CONFIG, NAVER_CONFIG

"""비즈니스, 서비스 로직을 구현 하는 파일 입니다."""


class CommonDecodeSignerUser(APIView):

    permission_classes = (AllowAny,)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.code = None
        self.signer = None
        self.user = None

    @abstractmethod
    def get(self, request, *args, **kwargs):
        pass

    def decode_signer(self, request):
        self.code = request.GET.get("code", "")
        self.signer = TimestampSigner()
        try:
            decoded_user_email = signing.loads(self.code)
            email = self.signer.unsign(decoded_user_email, max_age=60 * 3)
            self.user = CustomUser.objects.get(email=email)

        except SignatureExpired:
            return Response({"error": "expired time"}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return self.handle_save_user(request)

    @abstractmethod
    def handle_save_user(self, request, *args, **kwargs):
        pass


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


class SocialLoginAPIView(APIView):

    permission_classes = (AllowAny, IsLoggedIn)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.client_id = None
        self.redirect_uri = None
        self.login_uri = None

    @abstractmethod
    def get(self, request, *args, **kwargs):
        pass

    def kakao_login(self):
        self.client_id = KAKAO_CONFIG["REST_API_KEY"]
        self.redirect_uri = KAKAO_CONFIG["REDIRECT_URIS"]
        self.login_uri = KAKAO_CONFIG["LOGIN_URI"]
        url = f"{self.login_uri}?client_id={self.client_id}&redirect_uri={self.redirect_uri}&response_type=code"

        return url

    def google_login(self):
        self.client_id = GOOGLE_CONFIG["CLIENT_ID"]
        self.redirect_uri = GOOGLE_CONFIG["REDIRECT_URIS"]
        self.login_uri = GOOGLE_CONFIG["LOGIN_URI"]
        scope = GOOGLE_CONFIG["SCOPE"]

        url = f"{self.login_uri}?client_id={self.client_id}&redirect_uri={self.redirect_uri}&response_type=code&scope={scope}"

        return url

    def naver_login(self):
        self.client_id = NAVER_CONFIG["CLIENT_ID"]
        self.redirect_uri = NAVER_CONFIG["REDIRECT_URIS"]
        self.login_uri = NAVER_CONFIG["LOGIN_URI"]
        state = signing.dumps(self.client_id)

        url = f"{self.login_uri}?client_id={self.client_id}&redirect_uri={self.redirect_uri}&response_type=code&state={state}"

        return url


class SocialCallbackAPIView(APIView):

    permission_classes = (AllowAny, IsLoggedIn)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @abstractmethod
    def get(self, request, *args, **kwargs):
        pass

    @staticmethod
    def get_code(request):
        code = request.query_params.get("code")

        if not code:
            return Response({"error": "Code Not Found"}, status=status.HTTP_400_BAD_REQUEST)

        return code

    @staticmethod
    def get_state(request):
        state = request.query_params.get("state")

        if not state:
            return Response({"error": "State Not Found"}, status=status.HTTP_400_BAD_REQUEST)

        return state

    @staticmethod
    def token_data(grant_type, client_id, client_secret, redirect_uri, code, **kwargs):

        token_request_data = {
            "grant_type": grant_type,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "code": code,
        }

        token_headers = {
            "Content-type": kwargs.get("content_type"),
        }

        if kwargs.get("host"):
            token_headers["Host"] = kwargs.get("host")

        if kwargs.get("state"):
            token_request_data["state"] = kwargs.get("state")

        return token_request_data, token_headers

    @staticmethod
    def requests_post_token(token_uri, token_request_data, **kwargs):
        try:
            if kwargs.get("token_headers"):
                token_response = requests.post(
                    token_uri,
                    data=token_request_data,
                    headers=kwargs.get("token_headers"),
                )
            else:
                token_response = requests.post(
                    token_uri,
                    data=token_request_data,
                )

        except Exception as e:
            return Response({"error post token": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return token_response

    @staticmethod
    def transfer_token(token_response):
        token_json = token_response.json()
        access_token = token_json.get("access_token")
        access_token = f"Bearer {access_token}"
        auth_headers = {
            "Authorization": access_token,
        }

        return auth_headers

    @staticmethod
    def requests_get_user(profile_uri, auth_headers):
        try:
            user_info_response = requests.get(
                profile_uri,
                headers=auth_headers,
            )

        except Exception as e:
            return Response({"error get user": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return user_info_response

    @staticmethod
    def user_info_json(user_info_response):
        return user_info_response.json()

    @staticmethod
    def user_data(email, username, social_type):
        return {"email": email, "username": username, "social_type": social_type}

    @staticmethod
    def get_user_info_json(self, **kwargs):
        # Google
        if kwargs.get("host") and kwargs.get("content_type"):
            token_request_data, token_headers = self.token_data(
                grant_type=self.grant_type,
                client_id=self.client_id,
                client_secret=self.client_secret,
                redirect_uri=self.redirect_uri,
                code=self.code,
                content_type=self.content_type,
                host=self.host,
            )

        # Naver
        elif kwargs.get("state"):
            token_request_data, token_headers = self.token_data(
                grant_type=self.grant_type,
                client_id=self.client_id,
                client_secret=self.client_secret,
                redirect_uri=self.redirect_uri,
                code=self.code,
                state=self.state,
            )

        # Kakao
        else:
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
