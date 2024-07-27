from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
#from encrypted_model_fields.fields import EncryptedCharField


class Book(models.Model):
#    id = models.BigAutoField(primary_key=True)
    isbn = models.CharField(max_length=13, unique=True) # validate
    authors = models.CharField(max_length=255)
    category = models.CharField(max_length=100)
    title = models.CharField(max_length=255)
    cover_picture = models.ImageField(upload_to='book_covers/')
    edition = models.CharField(max_length=50)
    publisher = models.CharField(max_length=100)
    publication_year = models.PositiveIntegerField()
    quantity_in_stock = models.IntegerField()
    minimum_threshold = models.IntegerField()
    buying_price = models.DecimalField(max_digits=10, decimal_places=2)
    selling_price = models.DecimalField(max_digits=10, decimal_places=2)
    def __str__(self):
        return self.title
    
class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, first_name, last_name, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, first_name=first_name, last_name=last_name, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    def create_superuser(self, email, username, first_name, last_name, password=None, **extra_fields):
        extra_fields.setdefault('is_admin', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_suspended', False)
        return self.create_user(email, username, first_name, last_name, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
#    id = models.BigAutoField(primary_key=True)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=50, unique=True)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    phone = models.CharField(max_length=15, blank=True, null=True)
    address = models.CharField(max_length=255, blank=True, null=True)
    state = models.CharField(max_length=13, blank=True, null=True) # add validator
    city = models.CharField(max_length=25, blank=True, null=True)
    zip = models.CharField(max_length=5, blank=True, null=True)
    cc_num = models.CharField(max_length=16, blank=True, null=True) # add validator
    cc_name = models.CharField(max_length=100, blank=True, null=True) # add validator
    cc_expiry = models.CharField(max_length=5, blank=True, null=True) # add val
    cvc = models.CharField(max_length=3, blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_suspended = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']

    def __str__(self):
        return self.email

    @property
    def is_staff(self):
        return self.is_admin
