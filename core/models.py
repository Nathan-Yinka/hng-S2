from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.core.validators import EmailValidator

class UserManager(BaseUserManager):
    def create_user(self, email, first_name, last_name, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, first_name=first_name, last_name=last_name, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, first_name, last_name, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, first_name, last_name, password, **extra_fields)

class User(AbstractBaseUser):
    userId = models.UUIDField(primary_key=True, editable=False)
    firstName = models.CharField(max_length=30, null=False)
    lastName = models.CharField(max_length=30, null=False)
    email = models.EmailField(unique=True, null=False, validators=[EmailValidator()])
    password = models.CharField(max_length=128, null=False)
    phone = models.CharField(max_length=15, blank=True, null=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def __str__(self):
        return self.email

class Organisation(models.Model):
    orgId = models.UUIDField(primary_key=True, editable=False)
    name = models.CharField(max_length=100, null=False)
    description = models.TextField(blank=True, null=True)
    users = models.ManyToManyField(User, related_name='organisations')

    def __str__(self):
        return self.name
