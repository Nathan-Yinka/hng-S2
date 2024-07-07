from django.contrib.auth import get_user_model,authenticate

from rest_framework import serializers
from .models import Organisation


User = get_user_model()


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['userId', 'firstName', 'lastName', 'email', 'phone']


class OrganisationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organisation
        fields = ['orgId', 'name', 'description']

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['userId','password', 'firstName', 'lastName', 'email', 'phone']

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            firstName=validated_data['firstName'],
            lastName=validated_data['lastName'],
            password=validated_data['password'],
            phone=validated_data.get('phone', '')
        )
        Organisation.objects.create(name=f"{validated_data['firstName']}'s Organisation").users.add(user)
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(email=data['email'], password=data['password'])
        data['user'] = user
        return data
