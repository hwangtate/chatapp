from abc import abstractmethod

import requests
from django.contrib.auth import login
from django.core import signing
from django.core.signing import TimestampSigner, SignatureExpired

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import CustomUser
from accounts.serializers import SocialRegisterSerializer
from coreapp.settings.development import GOOGLE_CONFIG, NAVER_CONFIG


class CommonDecodeSignerUser:

    def __init__(self):
        self.user = None

    def decode_signer(self, request):
        code = request.GET.get("code", "")
        signer = TimestampSigner()
        try:
            decoded_user_email = signing.loads(code)
            email = signer.unsign(decoded_user_email, max_age=60 * 3)
            self.user = CustomUser.objects.get(email=email)

        except SignatureExpired:
            return Response({"error": "expired time"}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return self.handle_save_user(request)

    @abstractmethod
    def handle_save_user(self, request):
        pass


class SocialLogin:

    @abstractmethod
    def get_social_provider_data(self):
        pass

    def social_login(self, kakao=None, google=None, naver=None):
        if kakao:
            url = self.basic_url
            return url

        if google:
            scope = GOOGLE_CONFIG["SCOPE"]
            url = self.basic_url + f"&scope={scope}"
            return url

        if naver:
            state = signing.dumps(NAVER_CONFIG["CLIENT_ID"])
            url = self.basic_url + f"&state={state}"
            return url

        return Response({"error": "invalid parameter value"}, status=status.HTTP_400_BAD_REQUEST)

    @property
    def basic_url(self):
        client_id, redirect_uri, login_uri = self.get_social_provider_data()
        return f"{login_uri}?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code"


class SocialLoginCallback(APIView):

    token_request_data = None
    profile_uri = None
    token_uri = None
    code = None
    state = None

    @abstractmethod
    def get_social_provider_data(self, request):
        pass

    def requests_post_token(self):
        self.token_request_data["code"] = self.code
        try:
            token_response = requests.post(
                self.token_uri,
                data=self.token_request_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            return token_response

        except Exception as e:
            return Response({"error post token": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def get_access_token_from_response(self):
        token_response = self.requests_post_token()
        token_json = token_response.json()

        return token_json.get("access_token")

    def requests_get_user(self):
        try:
            user_info_response = requests.get(
                self.profile_uri,
                headers={
                    "Content-type": "application/x-www-form-urlencoded",
                    "Authorization": f"Bearer {self.get_access_token_from_response()}",
                },
            )

            return user_info_response

        except Exception as e:
            return Response({"error get user": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def get_user_info_json(self):
        user_info_data = self.requests_get_user().json()

        return user_info_data

    def social_login_or_register(self, request, data):
        if CustomUser.objects.filter(**data).exists():
            user = CustomUser.objects.get(**data)
            login(request, user)

            return Response(data=data, status=status.HTTP_200_OK)
        serializer = SocialRegisterSerializer(data=data)

        if serializer.is_valid():
            user = serializer.save()
            login(request, user)

            return Response(data=data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
