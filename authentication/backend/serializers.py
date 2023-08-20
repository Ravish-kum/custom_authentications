from rest_framework import serializers
from .models import User
class UserSerializer(serializers.ModelSerializer):
    phone_number = serializers.CharField(required =True)
    status = serializers.BooleanField(required =False)
    date_of_birth =serializers.CharField(required =True)
    student_class = serializers.CharField(required =True)
    student_image =serializers.ImageField(required=False)
    
    class Meta:
        model = User
        fields = ['id', 'phone_number','username', 'email','first_name', 'last_name', 'password', 'is_superuser', 'is_staff',
                  'status','date_of_birth','student_class','student_image']
        extra_kwargs = {
            'username': {'required': True, 'allow_blank': False},
            'phone_number': {'required': True, 'allow_blank': False,'read_only': True},
            'password': {'required': True,'read_only': True},
            'email': {},
            'first_name': {'required': True},
            'last_name': {'required': True},
            'is_superuser': {},
            'is_staff': {},
            'status':{'required': False,'read_only': True},
            'date_of_birth':{'required': True},
            'student_class':{'required': True},
            'student_image':{'required': False}
        }

    def create(self, validated_data):
        extra_fields = {
            'phone_number': validated_data.get('phone_number', ''),
            'date_of_birth': validated_data.get('date_of_birth', ''),
            'student_class': validated_data.get('student_class', ''),
            'student_image': validated_data.get('student_image', ''), 
            'first_name': validated_data.get('first_name', ''), 
            'last_name': validated_data.get('last_name', ''),            
        }

        myuser = User.objects.create_user(
            username=validated_data.get('username', ''),
            password=validated_data.get('password', ''),
            **extra_fields
        )

        if myuser is None:
            raise serializers.ValidationError('Unable to create user with given data.')

        return myuser
    
    def validate_phone_number(self, value):
        instance = self.instance
        if instance and value != instance.phone_number:
            raise serializers.ValidationError("Cannot change phone number.")
        return value

    def validate_status(self, value):
        instance = self.instance
        if instance and value != instance.status:
            raise serializers.ValidationError("Cannot change status.")
        return value