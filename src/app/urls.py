from django.urls import path
from . views import *

urlpatterns = [
    path("api/login/", LoginAPIView.as_view(), name="api-login"),
    path("api/logout", LogoutAPIView.as_view(), name="api-logout"),  
]
