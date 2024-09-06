from abc import abstractmethod

import requests
from django.contrib.auth import login
from django.core import signing
from django.core.signing import TimestampSigner, SignatureExpired

from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from accounts.models import CustomUser
from accounts.permissions import IsLoggedIn
from accounts.serializers import SocialRegisterSerializer
from coreapp.settings.development import GOOGLE_CONFIG


class CommonDecodeSignerUser:

    def __init__(self):
        self.code = None
        self.signer = None
        self.user = None

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
    def handle_save_user(self, request):
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


class SocialLogin:

    def __init__(self):
        self.client_id = None
        self.redirect_uri = None
        self.login_uri = None

    def social_login(self, kakao=None, google=None, naver=None):
        if kakao:
            url = self.basic_url()
            return url

        if google:
            scope = GOOGLE_CONFIG["SCOPE"]
            url = self.basic_url() + f"&scope={scope}"
            return url

        if naver:
            state = signing.dumps(self.client_id)
            url = self.basic_url() + f"&state={state}"
            return url

        return Response({"error": "invalid parameter value"}, status=status.HTTP_400_BAD_REQUEST)

    def basic_url(self):
        return f"{self.login_uri}?client_id={self.client_id}&redirect_uri={self.redirect_uri}&response_type=code"


class SocialLoginCallback:
    """
    2번 이상 사용하는 변수들은 인스턴스 변수로 선언함
    """

    permission_classes = (AllowAny, IsLoggedIn)

    def __init__(self):
        self.grant_type = None
        self.client_id = None
        self.client_secret = None
        self.redirect_uri = None
        self.content_type = None
        self.profile_uri = None

        self.token_uri = None
        self.token_headers = None
        self.token_request_data = None
        self.token_response = None

        self.code = None
        self.state = None
        self.host = None

        self.auth_headers = None
        self.user_info_response = None

    def get_code(self, request):
        self.code = request.query_params.get("code", None)

        return self.code

    def get_state(self, request):
        self.state = request.query_params.get("state", None)

        return self.state

    def token_data(self):
        self.token_request_data = {
            "grant_type": self.grant_type,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "code": self.code,
        }

        self.token_headers = {
            "Content-type": self.content_type,
        }

        if self.host is not None:
            self.token_headers["host"] = self.host

        if self.state is not None:
            self.token_request_data["state"] = self.state

        return self.token_request_data, self.token_headers

    def requests_post_token(self):
        try:
            self.token_response = requests.post(
                self.token_uri,
                data=self.token_request_data,
                headers=self.token_headers,
            )

            return self.token_response

        except Exception as e:
            return Response({"error post token": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def transfer_token(self):
        token_json = self.token_response.json()
        access_token = token_json.get("access_token")
        self.auth_headers = {
            "Authorization": f"Bearer {access_token}",
        }

        return self.auth_headers

    def requests_get_user(self):
        try:
            self.user_info_response = requests.get(
                self.profile_uri,
                headers=self.auth_headers,
            )

            return self.user_info_response

        except Exception as e:
            return Response({"error get user": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def user_info_json(self):
        user_info_data = self.user_info_response.json()

        return user_info_data

    def get_user_info_json(self, request):
        self.code = self.get_code(request)
        self.state = self.get_state(request)
        self.token_request_data, self.token_headers = self.token_data()
        self.token_response = self.requests_post_token()
        self.auth_headers = self.transfer_token()
        self.user_info_response = self.requests_get_user()

        user_info_data = self.user_info_json()

        return user_info_data

    @staticmethod
    def get_user_data(email, username, social_type):
        user_data = {"email": email, "username": username, "social_type": social_type}

        return user_data
