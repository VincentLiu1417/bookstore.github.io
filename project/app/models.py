from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from decimal import Decimal
#from encrypted_model_fields.fields import EncryptedCharField


class Book(models.Model):
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

class Cart(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    promotion = models.ForeignKey('Promotion', on_delete=models.SET_NULL, null=True, blank=True)

    def apply_promotion(self, promotion):
        self.promotion = promotion
        self.save()

class CartItem(models.Model):
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE)
    book = models.ForeignKey(Book, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()

    def update_quantity(self, quantity):
        self.quantity = quantity
        self.save()
        
class ShippingBillingInfo(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    address = models.CharField(max_length=255)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    zip_code = models.CharField(max_length=10)
    country = models.CharField(max_length=100)
    delivery_instructions = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return f'{self.user.username} - {self.address}'
    
class PaymentInfo(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    card_number = models.CharField(max_length=16)
    expiration_date = models.CharField(max_length=5)
    cvv = models.CharField(max_length=3)

    def __str__(self):
        return f'{self.user.username} - {self.card_number}'

class Promotion(models.Model):
    code = models.CharField(max_length=50, unique=True)
    discount = models.DecimalField(max_digits=5, decimal_places=2)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.code
    
class Order(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    order_number = models.CharField(max_length=12, unique=True)
    date_ordered = models.DateTimeField(auto_now_add=True)
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    tax = models.DecimalField(max_digits=10, decimal_places=2)
    shipping_fee = models.DecimalField(max_digits=10, decimal_places=2)
    order_total = models.DecimalField(max_digits=10, decimal_places=2)
    shipping_info = models.ForeignKey('ShippingBillingInfo', on_delete=models.SET_NULL, null=True, blank=True)
    payment_info = models.ForeignKey('PaymentInfo', on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.order_number

class OrderItem(models.Model):
    order = models.ForeignKey(Order, related_name='items', on_delete=models.CASCADE)
    book = models.ForeignKey(Book, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()

    def __str__(self):
        return f"{self.quantity} x {self.book.title}"