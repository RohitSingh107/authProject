from rest_framework import serializers

from jwt_auth_api.models import User

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

  # Validating Password and Confirm Password while Registration
        # def validate(self, attrs):
            # password = attrs.get('password')
            # password2 = attrs.get('password2')
            # if password != password2:
            #   raise serializers.ValidationError("Password and Confirm Password doesn't match")
            # return attrs

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
