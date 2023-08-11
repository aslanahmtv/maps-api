from django.contrib.auth.models import User, Group
from django.db.models import Q
from rest_framework import serializers
from rest_framework.authtoken.models import Token

from map.models import  Route
from mapsbackend import settings


class UserRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        label="Email Address"
    )

    password = serializers.CharField(
        required=True,
        label="Password",
        style={'input_type': 'password'}
    )

    password_2 = serializers.CharField(
        required=True,
        label="Confirm Password",
        style={'input_type': 'password'}
    )

    class Meta(object):
        model = User
        fields = ['username', 'email', 'password', 'password_2']

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists.")
        return value

    def validate_password(self, value):
        if len(value) < getattr(settings, 'PASSWORD_MIN_LENGTH', 8):
            raise serializers.ValidationError(
                "Password should be atleast %s characters long." % getattr(settings, 'PASSWORD_MIN_LENGTH', 8)
            )
        return value

    def validate_password_2(self, value):
        data = self.get_initial()
        password = data.get('password')
        if password != value:
            raise serializers.ValidationError("Passwords doesn't match.")
        return value

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Email already exists.")
        return value



    def create(self, validated_data):
        user_data = {
            'username': validated_data.get('username'),
            'email': validated_data.get('email'),
            'password': validated_data.get('password'),

        }


        user = User.objects.create(
            username=validated_data.get('username'),
            email = validated_data.get('email'),
            password = validated_data.get('password'),


        )


        return validated_data


class UserLoginSerializer(serializers.ModelSerializer):

    username = serializers.CharField(
        required=False,
        allow_blank=True,
        write_only=True,
    )

    email = serializers.EmailField(
        required=False,
        allow_blank=True,
        write_only=True,
        label="Email Address"
    )

    token = serializers.CharField(
        allow_blank=True,
        read_only=True
    )

    password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'}
    )

    class Meta(object):
        model = User
        fields = ['email', 'username', 'password', 'token']

    def validate(self, data):
        email = data.get('email', None)
        username = data.get('username', None)
        password = data.get('password', None)

        if not email and not username:
            raise serializers.ValidationError("Please enter username or email to login.")

        user = User.objects.filter(
            Q(email=email) | Q(username=username)
        ).exclude(
            email__isnull=True
        ).exclude(
            email__iexact=''
        ).distinct()

        if user.exists() and user.count() == 1:
            user_obj = user.first()
        else:
            raise serializers.ValidationError("This username/email is not valid.")

        if user_obj:
            if not user_obj.check_password(password):
                raise serializers.ValidationError("Invalid credentials.")

        if user_obj.is_active:
            token, created = Token.objects.get_or_create(user=user_obj)
            data['token'] = token
        else:
            raise serializers.ValidationError("User not active.")

        return data




class GetRouteSerializer(serializers.ModelSerializer):

    class Meta:
        model = Route
        fields = "__all__"


class SetRouteSerializer(serializers.ModelSerializer):
    coords = serializers.IntegerField(
        required=True,
        label="Coordinations",)

    name = serializers.CharField(
        required=True,
        label="Name"
    )
    description = serializers.CharField(
        required=False,
        label="Description"
    )
    class Meta:
        model = Route
        fields = "__all__"

    def create(self, validated_data):
        route = Route.objects.create(
            user = validated_data.get("user"),
            coords = validated_data.get("coords"),
            name =  validated_data.get("name"),
            description = validated_data.get("description")
        )
        token, created = Token.objects.get_or_create(user=validated_data.get("user"))
        return validated_data