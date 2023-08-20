from typing import Any
from django.db import models
from django.contrib.auth.models import PermissionsMixin,AbstractUser
from django.contrib.auth.base_user import BaseUserManager
from  django.utils import timezone
# Create your models here.

class UserManager(BaseUserManager):
    def _create_user(self, username, email, password, is_staff, is_superuser,status =False,**extra_fields):
        now = timezone.now()
        if not username:
            raise ValueError(('The given username must be set'))
        email = self.normalize_email(email)
        user = User(username=username, email=email,
                          is_staff=is_staff, status= status,
                          is_superuser=is_superuser, last_login=now,
                          date_joined=now, **extra_fields)
        user.set_password(str(password))
        user.save(using=self._db)
        return user
    
    def create_user(self, username, password, email=None, **extra_fields):
        return self._create_user(username, email, password, is_staff=False ,is_superuser=False,status=False,
                                 **extra_fields)

    def create_superuser(self, password, email=None, username='admin', **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self._create_user(username=username,email=email ,password=password, status = True, **extra_fields)

class User(AbstractUser,PermissionsMixin):
    phone_number = models.CharField(max_length =14,unique=True)
    status = models.BooleanField(default=False)
    date_of_birth =models.CharField(max_length=20)
    student_class = models.CharField(max_length=20)
    student_image =models.ImageField(null=True,blank=True)
    REQUIRED_FIELDS=[]
    USERNAME_FIELD ='phone_number'
    objects = UserManager()
