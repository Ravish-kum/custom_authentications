from django.shortcuts import render
from rest_framework.views import APIView
from .models import User
from .serializers import UserSerializer
from rest_framework.response import Response
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, logout, login,get_user_model
User = get_user_model()
import jwt
from rest_framework import generics, status
from django.conf import settings
import json
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.core import serializers
from rest_framework_simplejwt.authentication import JWTAuthentication
# Create your views here.

''' function used for fetching jwt access and refresh tokens from authentications headers '''

def get_payload_from_token(authorization_header):
    secret_key = settings.SECRET_KEY

    if authorization_header is None:
        return None, Response({'error': 'Authorization header missing',"status_code":401}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        access_token = authorization_header.split(' ')[1]
    except IndexError:
        return None, Response({'error': 'Invalid Authorization header',"status_code":401}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        data = jwt.decode(access_token, secret_key, algorithms=['HS256'])['payload']
        access_token_payload = json.loads(data)
        payload = access_token_payload[0]['pk']

    except jwt.exceptions.InvalidSignatureError:
        return None, Response({'error': 'Invalid token signature',"status_code":401}, status=status.HTTP_401_UNAUTHORIZED)
    except jwt.exceptions.DecodeError:
        return None, Response({'error': 'Invalid token format',"status_code":401}, status=status.HTTP_401_UNAUTHORIZED)

    return payload, None


class Signup(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        phone_number = request.data.get('phone_number')
        existance = User.objects.filter(phone_number=phone_number).exists()
        if existance:
            return Response('user already exists')
        else:
            try:
                if serializer.is_valid(raise_exception=True):
                    serializer.save()
                return Response({"message":"user successfully formed","status":200})
            except Exception as e:
                print
                return Response("server error")
            
    def get(self,request):
        instance = User.objects.all()
        serializer = UserSerializer(instance,many=  True)
        return Response({'all_users':serializer.data})

class Signin(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        phone_number = request.data.get('phone_number')
        password = request.data.get('password')
        print(phone_number)
        print(password,type(password))
        user = User.objects.filter(phone_number=phone_number).values('password')
        print(user)
        myuser = authenticate(phone_number=phone_number, password=password)
        
        User_exist = User.objects.filter(phone_number=phone_number).exists()
        User_exist3 = User.objects.filter(phone_number=phone_number).values()
        print(User_exist)
        print(User_exist3)
        if User_exist != True :
            return Response({'error': 'not a user or wrong phone number','status_code':409})
        print(myuser)
        if myuser is not None:
            user = User.objects.get(phone_number=phone_number)
            print(user)
            refresh_token = RefreshToken.for_user(user)
            access_token_payload = serializers.serialize('json', [user, ])
            access_token = refresh_token.access_token
            access_token['payload'] = access_token_payload
            login(request, myuser)
            
            return Response({
                'message':'signin success',
                'status_code':200,
                'refresh_token': str(refresh_token),
                'access': str(access_token), })

        else:
            return Response({'error': 'Invalid password',"status_code":400})
        
from django.views.decorators.csrf import csrf_exempt
@csrf_exempt
def signin(request):
    view = Signin.as_view()
    response = view(request)
    return response

class Profile(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        payload, error_response = get_payload_from_token(request.META.get('HTTP_AUTHORIZATION'))
        if error_response:
            return error_response
        # Extract the customer ID from the payload
        if not payload:
            return Response({'error': 'Customer ID not found in token payload',"status_code":401}, status=status.HTTP_401_UNAUTHORIZED)
        
        instance = User.objects.filter(id=payload).first()
        if instance is not None:
            serializer = UserSerializer(instance, request.data, partial =True )
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response(serializer.data)
            else:
                return Response({'error': 'server error',"status_code":400})
        else:
            return Response({'error': 'not a user',"status_code":409})