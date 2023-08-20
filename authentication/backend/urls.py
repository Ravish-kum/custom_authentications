from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from django.urls import path
from .views import Signup,signin,Profile
from .views import signin

urlpatterns = [
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('signup/',Signup.as_view(),name='signup'),
    path('signin/', signin,name='signin'),
    path('profile/',Profile.as_view(),name='profile')
]