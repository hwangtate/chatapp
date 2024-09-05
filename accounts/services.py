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
from coreapp.settings.development import GOOGLE_CONFIG

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


class SocialCallback:

    permission_classes = (AllowAny, IsLoggedIn)

    def __init__(self):
        self.grant_type = None
        self.client_id = None
        self.client_secret = None
        self.redirect_uri = None
        self.content_type = None
        self.profile_uri = None

        self.code = None
        self.state = None
        self.host = None

        self.token_uri = None
        self.token_headers = None
        self.token_request_data = None
        self.token_response = None

        self.auth_headers = None

        self.user_info_response = None
        self.user_info_json = None
        self.user_data = None

    def get_code(self, request):
        self.code = request.query_params.get("code")

        if not self.code:
            return Response({"error": "Code Not Found"}, status=status.HTTP_400_BAD_REQUEST)

        return self.code

    def get_state(self, request):
        self.state = request.query_params.get("state")

        if not self.state:
            return Response({"error": "State Not Found"}, status=status.HTTP_400_BAD_REQUEST)

        return self.state

    def token_data(self, grant_type, client_id, client_secret, redirect_uri, code, content_type, **kwargs):
        self.token_request_data = {
            "grant_type": grant_type,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "code": code,
            "content_type": content_type,
        }

        self.token_headers = {
            "Content-type": kwargs.get("content_type"),
        }

        if kwargs.get("host"):
            self.token_headers["host"] = kwargs.get("host")

        if kwargs.get("state"):
            self.token_request_data["state"] = kwargs.get("state")

        return self.token_request_data, self.token_headers

    def requests_post_token(self, token_uri, token_request_data, **kwargs):
        try:
            self.token_response = requests.post(
                token_uri,
                data=token_request_data,
                headers=kwargs.get("token_headers"),
            )

            return self.token_response

        except Exception as e:
            return Response({"error post token": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def transfer_token(self, token_response):
        token_json = token_response.json()
        access_token = token_json.get("access_token")
        self.auth_headers = {
            "Authorization": f"Bearer {access_token}",
        }

        return self.auth_headers

    def requests_get_user(self, profile_uri, auth_headers):
        try:
            self.user_info_response = requests.get(
                profile_uri,
                headers=auth_headers,
            )

            return self.user_info_response

        except Exception as e:
            return Response({"error get user": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def user_info_json(self, user_info_response):
        self.user_info_json = user_info_response.json()

        return self.user_info_json

    def get_user_info_json(self, **kwargs):
        # kakao(basic)
        self.token_request_data, self.token_headers = self.token_data(
            grant_type=self.grant_type,
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=self.redirect_uri,
            code=self.code,
            content_type=self.content_type,
        )

        # Google
        if kwargs.get("host"):
            self.token_request_data["host"] = self.host

        # Naver
        elif kwargs.get("state"):
            self.token_request_data["state"] = self.state

        self.token_response = self.requests_post_token(
            token_uri=self.token_uri,
            token_request_data=self.token_request_data,
            token_headers=self.token_headers,
        )

        self.auth_headers = self.transfer_token(
            token_response=self.token_response,
        )

        self.user_info_response = self.requests_get_user(
            profile_uri=self.profile_uri,
            auth_headers=self.auth_headers,
        )

        self.user_info_json = self.user_info_json(self.user_info_response)

        return self.user_info_json

    def user_data(self, email, username, social_type):
        self.user_data = {"email": email, "username": username, "social_type": social_type}

        return self.user_data
