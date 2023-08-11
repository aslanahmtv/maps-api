
from django.http import HttpResponse
from django.shortcuts import render
from rest_framework import generics, permissions, status, views
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from map import serializers
from map.models import Route


# Create your views here.

def index(request):
    return HttpResponse("test")

class UserRegistrationAPIView(generics.CreateAPIView):
    """
    Endpoint for user registration.
    """

    permission_classes = (permissions.AllowAny, )
    serializer_class = serializers.UserRegistrationSerializer
    queryset = User.objects.all()


class UserLoginAPIView(views.APIView):
    """
    Endpoint for user login. Returns authentication token on success.
    """

    permission_classes = (permissions.AllowAny, )
    serializer_class = serializers.UserLoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLogoutAPIView(views.APIView):
    def get(self, request, format=None):
        # simply delete the token to force a login
        request.user.auth_token.delete()
        return Response(status=status.HTTP_200_OK)

class GetRoutesAPIVIew(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = serializers.GetRouteSerializer

    def get_queryset(self):
        key = self.request.key
        user = Token.objects.get(key=key).user
        return Response(Route.objects.filter(user=user))

class SetRoutesAPIView(generics.CreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = serializers.SetRouteSerializer







