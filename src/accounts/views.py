from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.github.views import GitHubOAuth2Adapter
from dj_rest_auth.registration.views import SocialLoginView
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from .models import UserProfile
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView


class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter

    def get_response(self):
        response = super().get_response()
        
        refresh = RefreshToken.for_user(self.user)
        response.data['access_token'] = str(refresh.access_token)
        response.data['refresh_token'] = str(refresh)

        user_data = {
            "id": self.user.id,
            "email": self.user.email,
            "username": self.user.username,
            "first_name": self.user.first_name,
            "last_name": self.user.last_name,
            "profile_image": self.get_profile_image(self.user),
        }
        self.save_user_profile(user_data)
        response.data["user"] = user_data

        return response

    def get_profile_image(self, user):
        try:
            social_account = user.socialaccount_set.filter(provider='google').first()
            if social_account:
                return social_account.extra_data.get('picture')
            return None
        except Exception as e:
            return None

    def save_user_profile(self, user_data):
        user_instance, created = User.objects.get_or_create(username=user_data["username"])
        # if created:
        #     user_instance.first_name = user_data["first_name"]
        #     user_instance.last_name = user_data["last_name"]
        #     user_instance.email = user_data["email"]
        #     user_instance.save()
        user_profile, created = UserProfile.objects.get_or_create(user=user_instance)
        user_profile.profile_image = user_data.get("profile_image")
        user_profile.first_name = user_data.get("first_name")
        user_profile.last_name = user_data.get("last_name")
        user_profile.email = user_data.get("email")
        user_profile.save()


import requests
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status


class GitHubLogin(APIView):

    def post(self, request, *args, **kwargs):
        code = request.data.get('code')
        if not code:
            return Response({"detail": "Authorization code is missing"}, status=status.HTTP_400_BAD_REQUEST)

        access_token = self.get_access_token(code)

        if not access_token:
            return Response({"detail": "Failed to get access token from GitHub"}, status=status.HTTP_400_BAD_REQUEST)

        user_data = self.get_github_user_data(access_token)

        if not user_data:
            return Response({"detail": "Failed to get user data from GitHub"}, status=status.HTTP_400_BAD_REQUEST)

        user = self.create_or_update_user(user_data)

        return Response({
            "access_token": access_token,  
            "user": {
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                # "profile_image": user.profile.profile_image.url if user.profile.profile_image else None,
            }
        })

    def get_access_token(self, code):
        url = "https://github.com/login/oauth/access_token"
        data = {
            'client_id': '',  
            'client_secret': '',  
            'code': code,
            'redirect_uri': 'http://localhost:8000/callback/',  
        }
        headers = {'Accept': 'application/json'}
        response = requests.post(url, data=data, headers=headers)
        response_data = response.json()

        return response_data.get('access_token')

    def get_github_user_data(self, access_token):
        url = "https://api.github.com/user"
        headers = {'Authorization': f"token {access_token}"}
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            raise Exception(f"GitHub API request failed with status code {response.status_code}")
        
        user_data = response.json()
        email=None
        if not email:
            email_url = "https://api.github.com/user/emails"
            email_response = requests.get(email_url, headers=headers)
            if email_response.status_code == 200:
                emails = email_response.json()
                primary_email = next((e['email'] for e in emails if e.get('primary') and e.get('verified')), None)
                email = primary_email or ''  # Use the primary email if available and verified

        return {**user_data, 'email': email}

    def create_or_update_user(self, user_data):
        
        email = user_data.get('email', '')  
        user, created = get_user_model().objects.get_or_create(
            username=user_data['login'],
            defaults={
                'first_name': user_data.get('name', '').split()[0],
                'last_name': user_data.get('name', '').split()[1] if len(user_data.get('name', '').split()) > 1 else '',
                'email': email,
            }
        )

        if not created:
            user.first_name = user_data.get('name', '').split()[0]
            user.last_name = user_data.get('name', '').split()[1] if len(user_data.get('name', '').split()) > 1 else ''
            user.email = email
            user.save()

        user_profile, created = user.profile if hasattr(user, 'profile') else UserProfile.objects.get_or_create(user=user)
        user_profile.profile_image = user_data.get('avatar_url')  
        user_profile.save()

        return user

class UserDetailsView(APIView):
    authentication_classes = [JWTAuthentication]  # Use only JWTAuthentication
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user  # The user is automatically authenticated via JWT
        user_data = {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
        }
        return Response(user_data)