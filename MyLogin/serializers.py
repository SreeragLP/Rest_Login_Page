from django.conf import settings
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from MyLogin.models import UserAccount
from django.core.mail import send_mail


class UserAccountSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = UserAccount
        fields = ['username', 'email', 'password', 'confirm_password']
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        email_field = serializers.EmailField()
        try:
            email = email_field.to_internal_value(email)
        except serializers.ValidationError:
            raise serializers.ValidationError("Enter a valid email address.")

        if UserAccount.objects.filter(email=email).exists():
            raise serializers.ValidationError("Email address must be unique.")

        try:
            validate_password(password)
        except ValidationError as e:
            raise serializers.ValidationError({"password": e})

        if len(password) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")

        has_uppercase = any(char.isupper() for char in password)
        if not has_uppercase:
            raise serializers.ValidationError("Password must contain at least one uppercase letter.")

        has_special_character = any(char for char in password if char in "!@#$%^&*()-_=+[{]};:'\"|,.<>?")
        if not has_special_character:
            raise serializers.ValidationError("Password must contain at least one special character.")

        if password != confirm_password:
            raise serializers.ValidationError("Passwords do not match.")

        return data

    def create(self, validated_data):
        username = validated_data['username']
        email = validated_data['email']
        password = validated_data['password']

        user = UserAccount.objects.create(
            email=email,
            username=username,
            password=password,
        )

        subject = 'Account Activation'
        message = f'Thank you for registering with us, {username}! Your account has been successfully created.'
        from_email = settings.DEFAULT_FROM_EMAIL
        to_email = [email]

        try:
            send_mail(subject, message, from_email, to_email, fail_silently=False)
            print("Activation email sent successfully.")
        except Exception as e:
            print(f"Error sending activation email: {e}")

        return user




class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        user = UserAccount.objects.filter(email=email, password=password).first()

        if not user:
            raise serializers.ValidationError('Login failed. Invalid credentials.')

        data['user'] = user
        return data



class UpdatePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirm_new_password = serializers.CharField(required=True)



