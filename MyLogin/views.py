from django.conf import settings
from django.core.mail import send_mail
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from MyLogin.models import UserAccount
from MyLogin.serializers import  UserAccountSerializer,LoginSerializer,UpdatePasswordSerializer

from django.shortcuts import redirect





class RegisterAPIView(generics.CreateAPIView):
    queryset = UserAccount.objects.all()
    serializer_class = UserAccountSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        email = serializer.validated_data['email']
        username = serializer.validated_data['username']
        subject = 'Account Activation'
        message = f'Thank you for registering with us, {username}! Your account has been successfully created.'
        from_email = settings.DEFAULT_FROM_EMAIL

        try:
            send_mail(subject, message, from_email, [email], fail_silently=False)
            print("Activation email sent successfully.")
        except Exception as e:
            print(f"Error sending activation email: {e}")

        return Response({'message': 'User registered successfully. Check your email for confirmation.'},
                        status=status.HTTP_201_CREATED)


class LoginAPIView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)





class UpdatePasswordAPIView(APIView):
    permission_classes = []

    def post(self, request, *args, **kwargs):
        serializer = UpdatePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_email = request.data.get('email')
        old_password = request.data.get('current_password')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_new_password')

        try:
            user = UserAccount.objects.get(email=user_email, password=old_password)
        except UserAccount.DoesNotExist:
            return Response({'error': 'Invalid email or password.'}, status=status.HTTP_400_BAD_REQUEST)

        if new_password != confirm_password:
            return Response({'error': 'New passwords do not match.'}, status=status.HTTP_400_BAD_REQUEST)

        if not new_password:
            return Response({'error': 'New password cannot be empty.'}, status=status.HTTP_400_BAD_REQUEST)

        user.password = new_password
        user.save()

        subject = 'Password Update'
        message = f'your account password has been successfully updated.'

        from_email = settings.DEFAULT_FROM_EMAIL
        to_email = [user_email]
        send_mail(subject, message, from_email, to_email, fail_silently=False)

        return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)






