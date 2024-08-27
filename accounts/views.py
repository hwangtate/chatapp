from rest_framework.decorators import api_view
from rest_framework.response import Response

from accounts.models import CustomUser
from .serializers import UserSerializer


@api_view(["GET"])
def user_list(request):
    if request.method == "GET":
        user = CustomUser.objects.all()
        serializer = UserSerializer(user, many=True)
        return Response(serializer.data)


@api_view(["GET"])
def user_detail(request, pk):
    if request.method == "GET":
        user = CustomUser.objects.get(pk=pk)
        serializer = UserSerializer(user)
        return Response(serializer.data)
