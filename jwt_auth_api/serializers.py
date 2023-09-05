from datetime import date, datetime
from rest_framework import serializers
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from jwt_auth_api.models import User
from jwt_auth_api.utils import Util

class UserRegistrationSerializer(serializers.ModelSerializer):
  # # We are writing this becoz we need confirm password field in our Registratin Request
  # password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields = ['email', 'name', 'password', 'tc']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User(
            email=validated_data['email'],
            name=validated_data['name'],
            tc=validated_data['tc']
        )
        user.set_password(validated_data['password'])
        user.save()

        return user

class UserLoginSerializer(serializers.ModelSerializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    model = User
    fields = ['email', 'password']


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'name', 'id']


class UserChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    new_password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)

    class Meta:
        fields = ['old_password', 'password']

    def validate(self, attrs):
        op = attrs.get('old_password')
        np = attrs.get('new_password')
        user : User = self.context.get('user')
        if not user.check_password(op):
            raise serializers.ValidationError("Please enter current password correctly.") 
        if op == np:
            raise serializers.ValidationError("New password is same as old password.")
        user.set_password(np)
        user.save()

        return attrs

class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            euid = urlsafe_base64_encode(force_bytes(user.id))
            # print("euid is ", euid)
            token = PasswordResetTokenGenerator().make_token(user=user)

            link = 'http://localhost:8000/api/user/reset/' + euid + '/' + token

            body = "Click Following Link to Reset Your Password: " + link
            data= {
                "subject": "Reset Your Password",
                "body": body,
                "to_email": [user.email],
            }
            Util.send_email(data=data)
            # print("Password reset link: ", link)
            return attrs
        else:
            raise serializers.ValidationError('You are not a registered user.')


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        euid = self.context.get('uid')
        token = self.context.get('token')

        if password != password2:
            raise serializers.ValidationError("Password and confirm password do not match")
        try:
            uid = smart_str(urlsafe_base64_decode(euid))
        except DjangoUnicodeDecodeError as identifier:
            raise serializers.ValidationError("User id is not valid.")
        user = User.objects.get(id=uid)
        if not PasswordResetTokenGenerator().check_token(user=user, token=token):
            raise serializers.ValidationError("Token is expired or not valid.")
        user.set_password(password)
        user.save()

        data= {
            "subject": "Password Reset Successfull",
            "body": f"Password is successfully reset at {datetime.now()}",
            "to_email": [user.email],
        }
        Util.send_email(data=data)
        return attrs
