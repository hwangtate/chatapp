from abc import abstractmethod

from django.contrib.auth import login
from django.core import signing
from django.core.signing import TimestampSigner, SignatureExpired
from django.shortcuts import redirect

from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import CustomUser
from accounts.permissions import IsLoggedIn
from accounts.serializers import SocialRegisterSerializer
from coreapp.settings.development import (
    KAKAO_KEY_CONFIG,
    KAKAO_URI_CONFIG,
    GOOGLE_CONFIG,
)

"""비즈니스, 서비스 로직을 구현 하는 파일 입니다."""


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
            return Response(
                {"error": "expired time"}, status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return self.handle_save_user(request)

    @abstractmethod
    def handle_save_user(self, request, *args, **kwargs):
        pass


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
        self.client_id = KAKAO_KEY_CONFIG["KAKAO_REST_API_KEY"]
        self.redirect_uri = KAKAO_URI_CONFIG["KAKAO_REDIRECT_URI"]
        self.login_uri = KAKAO_URI_CONFIG["KAKAO_LOGIN_URI"]

        url = f"{self.login_uri}?client_id={self.client_id}&redirect_uri={self.redirect_uri}&response_type=code"

        return redirect(url)

    def google_login(self):
        self.client_id = GOOGLE_CONFIG["GOOGLE_CLIENT_ID"]
        self.redirect_uri = GOOGLE_CONFIG["GOOGLE_REDIRECT_URIS"]
        self.login_uri = GOOGLE_CONFIG["GOOGLE_LOGIN_URI"]
        scope = GOOGLE_CONFIG["GOOGLE_SCOPE"]

        url = f"{self.login_uri}?client_id={self.client_id}&redirect_uri={self.redirect_uri}&response_type=code&scope={scope}"

        return redirect(url)


class SocialCallBackAPIView(APIView):
    permission_classes = (AllowAny,)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def get(self, request, *args, **kwargs):
        pass
