from django.urls import path
from .views import GoogleLogin, GitHubLogin,UserDetailsView

urlpatterns = [
    path('social/google/', GoogleLogin.as_view(), name='google_login'),
    path('social/github/', GitHubLogin.as_view(), name='github_login'),
    path('userdetailsview/', UserDetailsView.as_view(), name='user_details'),
    path('github/callback/', GitHubLogin.as_view(), name='github_callback'),
]
