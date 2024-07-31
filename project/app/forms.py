from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm, AuthenticationForm, PasswordResetForm
from .models import CustomUser, Book, PaymentInfo, ShippingBillingInfo, Promotion, Cart, OrderItem, Order
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.sites.shortcuts import get_current_site

"""
class CheckoutForm(forms.ModelForm):
    class Meta:
        model = Order
        fields = ['shipping_info', 'payment_info']

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        super().__init__(*args, **kwargs)
        self.fields['shipping_info'].queryset = ShippingBillingInfo.objects.filter(user=self.user)
        self.fields['payment_info'].queryset = PaymentInfo.objects.filter(user=self.user)
    
    def clean(self):
        cleaned_data = super().clean()
        # Add any additional validation if needed
        return cleaned_data
"""
class CheckoutForm(forms.Form):
    shipping_address = forms.CharField(max_length=255)
    shipping_city = forms.CharField(max_length=100)
    shipping_state = forms.CharField(max_length=100)
    shipping_zip_code = forms.CharField(max_length=10)
    shipping_country = forms.CharField(max_length=100)
    
    # Drop-down menu for saved payment methods
    payment_method = forms.ModelChoiceField(queryset=PaymentInfo.objects.none(), empty_label="Select a payment method")
    
    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        if user:
            self.fields['payment_method'].queryset = PaymentInfo.objects.filter(user=user)

    def clean(self):
        cleaned_data = super().clean()
        # You can add custom validation here if needed
        return cleaned_data
class PromotionFactoryForm(forms.ModelForm):
    '''
    Works with views.create_promotion and models.Promotion in order to accept input and create promos.
    '''
    class Meta:
        model = Promotion
        fields = ['code', 'discount']

class BookSearchForm(forms.Form):
    query = forms.CharField(required=False,
                            widget=forms.TextInput(attrs={'class': 'search-bar','placeholder': 'Search by title, author, ISBN, or category'}))

class BookForm(forms.ModelForm):
    class Meta:
        model = Book
        fields = '__all__'
        widgets = {
            # YOU are here ...
            'isbn': forms.TextInput(attrs={'class': 'custom-input', 'label': 'ISBN', 'placeholder': 'ISBN'}),
            'authors': forms.TextInput(attrs={'class': 'custom-input', 'label': 'Author(s)', 'placeholder': 'Author(s)'}),
            'category': forms.TextInput(attrs={'class': 'custom-input', 'label': 'Category'}),
            'title': forms.TextInput(attrs={'class': 'custom-input', 'label': 'Title', 'placeholder': 'Title'}),
            'cover_picture': forms.ClearableFileInput(attrs={'class': 'custom-input', 'label': 'Cover Art'}),
            'edition': forms.TextInput(attrs={'class': 'custom-input', 'label': 'Edition'}),
            'publisher': forms.TextInput(attrs={'class': 'custom-input', 'label': 'Publisher'}),
            'publication_year': forms.TextInput(attrs={'class': 'custom-input', 'label':'Publication Year', 'placeholder': 'YYYY'}),
            'quantity_in_stock': forms.TextInput(attrs={'class': 'custom-input', 'label':'Quantity'}),
            'minimum_threshold': forms.TextInput(attrs={'class': 'custom-input', 'label':'Min Threshold'}),
            'buying_price': forms.TextInput(attrs={'class': 'custom-input', 'label':'Buy Price'}),
            'selling_price': forms.TextInput(attrs={'class': 'custom-input', 'label':'Sell Price'}),
        }


'''
class CustomSetPasswordForm(SetPasswordForm):
    new_password1 = forms.CharField(
        label="New password",
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        strip=False,
    )
    new_password2 = forms.CharField(
        label="New password confirmation",
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        strip=False,
    )
'''

class CustomPasswordResetForm(PasswordResetForm):
    email = forms.EmailField(max_length=254, required=True, widget=forms.EmailInput(attrs = {'autocomplete':'email'}))
    def save(self, domain_override=None,
             subject_template_name='registration/password_reset_subject.txt',
             email_template_name='registration/password_reset_email.html',
             use_https=False, token_generator=default_token_generator,
             from_email=None, request=None, html_email_template_name=None, extra_email_context=None):
        email = self.cleaned_data['email']
        for user in self.get_users(email):
            if not domain_override:
                current_site = get_current_site(request)
                site_name = current_site.name
                domain = current_site.domain
            else:
                site_name = domain = domain_override
            context = {
                'email':email,
                'domain':domain,
                'site_name':site_name,
                'uid':urlsafe_base64_encode(force_bytes(user.pk)),
                'token':token_generator.make_token(user),
                'protocol': 'https' if use_https else 'http', 
            }
            if extra_email_context is not None:
                context.update(extra_email_context)
            self.send_mail(
                subject_template_name, email_template_name, context, from_email, email, html_email_template_name=html_email_template_name,
            )

class CustomAuthenticationForm(AuthenticationForm):
    username = forms.CharField(label='Email or Username', widget=forms.TextInput(attrs={
        'class': 'custom-input',
        'placeholder': 'Email or Username',
        'style': 'width: 100%; background-color: #FDFBE4;'
        
    }))
    password = forms.CharField(
        label = 'Password',
        widget=forms.PasswordInput(
            attrs={
                'class': 'custom-input',
                'placeholder': 'Password'
            }
        )
    )
    

class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True,
                             widget=forms.EmailInput(attrs={'class': 'custom-input', 'placeholder': 'Email (Required)'}))
    username = forms.CharField(required=True,
                               widget=forms.TextInput(attrs={'class': 'custom-input', 'placeholder': 'Username (Required)'}))
    first_name = forms.CharField(required=True, widget=forms.TextInput(attrs={'class': 'custom-input', 'placeholder': 'First name (Required)'}))
    last_name = forms.CharField(required=True, widget=forms.TextInput(attrs={'class': 'custom-input', 'placeholder': 'Last name (Required)'}))
    phone = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'custom-input', 'placeholder': 'Phone number (Required)'}))
    address = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'custom-input', 'placeholder': 'Street Address'}))
    state = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'custom-input', 'placeholder': 'State'}))
    city = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'custom-input', 'placeholder': 'City'}))
    zip = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'custom-input', 'placeholder': 'Zip Code'}))
#    cc_number = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'custom-input', 'placeholder': 'Credit card number'}))
 #   cc_name = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'custom-input', 'placeholder': 'CC Name'}))
  #  cc_exp = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'custom-input', 'placeholder': 'CC Expiry'}))
   # cvc = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'custom-input', 'placeholder': 'CVC'}))
    # is_subscribed = forms.BooleanField(required=False)

    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(attrs={'class': 'custom-input', 'placeholder': 'Password'})
    )
    password2 = forms.CharField(
        label='Confirm Password',
        widget=forms.PasswordInput(attrs={'class': 'custom-input', 'placeholder': 'Confirm Password'})
    )

    is_subscribed = forms.BooleanField(required=False, initial=True, label='Join mailing list.')
    
    # TODO - add is_subscribed
    class Meta:
        model = CustomUser
        fields = ('email', 'username', 'first_name', 'last_name', 'password1', 'password2', 'phone', 'address', 'state', 'zip')
class UserProfileUpdateForm(UserChangeForm):
    password = None # exclude the password from the form
    class Meta:
        model = CustomUser
        fields = ('username', 'first_name', 'last_name', 'phone', 'address', 'state', 'zip')
        widgets = {
            'address' : forms.Textarea(attrs={'rows': 1, 'cols': 40}),
        }
        def clean_email(self):
            return self.instance.email # treat it as property that cannot be changed.

class PaymentInfoForm(forms.Form): ## smh shouldnt have made this one
    card_number = forms.CharField(required=False)
    expiration_date = forms.CharField(required=False)
    cvv = forms.CharField(required=False)
    class Meta:
        model = PaymentInfo
        fields = []
    def save(self, user, commit=True):
        payment_info = PaymentInfo(
            user=user,  # Set the user
            card_number=PaymentInfo.encrypt_value(self.cleaned_data['card_number']),
            expiration_date=PaymentInfo.encrypt_value(self.cleaned_data['expiration_date']),
            cvv=PaymentInfo.encrypt_value(self.cleaned_data['cvv'])
        )

        if commit:
            payment_info.save()
        return payment_info

### Nancy's ###
class ShippingBillingForm(forms.ModelForm):
    class Meta:
        model = ShippingBillingInfo
        fields = ['address', 'city', 'state', 'zip_code', 'country']
'''
class PaymentForm(forms.ModelForm):
    class Meta:
        model = PaymentInfo
        fields = ['card_number', 'expiration_date', 'cvv']
'''
class PromotionCodeForm(forms.ModelForm):
    class Meta:
        model = Promotion
        fields = ['code']
class PaymentForm(forms.ModelForm): ## smh shouldnt have made this one
    class Meta:
        model = PaymentInfo
        fields = ['card_number', 'expiration_date', 'cvv']
