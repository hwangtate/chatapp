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

    @staticmethod
    def get_code(request):
        code = request.query_params.get("code", None)
        return code

    @staticmethod
    def get_state(request):
        state = request.query_params.get("state", None)
        return state

    @abstractmethod
    def get_social_provider_data(self, request):
        pass

    @staticmethod
    def requests_post_token(token_uri, token_request_data, token_headers):
        try:
            token_response = requests.post(
                token_uri,
                data=token_request_data,
                headers=token_headers,
            )

            return token_response

        except Exception as e:
            return Response({"error post token": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    def transfer_token(token_response):
        token_json = token_response.json()
        access_token = token_json.get("access_token")
        auth_headers = {
            "Authorization": f"Bearer {access_token}",
        }

        return auth_headers

    @staticmethod
    def requests_get_user(profile_uri, auth_headers):
        try:
            user_info_response = requests.get(
                profile_uri,
                headers=auth_headers,
            )

            return user_info_response

        except Exception as e:
            return Response({"error get user": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    def user_info_json(user_info_response):
        user_info_data = user_info_response.json()

        return user_info_data

    def get_user_info_json(self, request):
        token_request_data, token_headers, social_uri = self.get_social_provider_data(request)
        token_response = self.requests_post_token(social_uri["token_uri"], token_request_data, token_headers)
        auth_headers = self.transfer_token(token_response)
        user_info_response = self.requests_get_user(social_uri["profile_uri"], auth_headers)

        user_info_data = self.user_info_json(user_info_response)

        return user_info_data

    @staticmethod
    def get_user_data(email, username, social_type):
        user_data = {"email": email, "username": username, "social_type": social_type}

        return user_data
