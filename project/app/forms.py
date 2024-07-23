from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm, AuthenticationForm, PasswordResetForm
from .models import CustomUser, Book
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.sites.shortcuts import get_current_site


class BookSearchForm(forms.Form):
    query = forms.CharField(required=False,
                            widget=forms.TextInput(attrs={'class': 'search-bar','placeholder': 'Search by title, author, ISBN, or category'}))

class BookForm(forms.ModelForm):
    class Meta:
        model = Book
        fields = '__all__'


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
        'placeholder': 'Email or Username'
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
    cc_number = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'custom-input', 'placeholder': 'Credit card number'}))
    cc_name = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'custom-input', 'placeholder': 'CC Name'}))
    cc_exp = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'custom-input', 'placeholder': 'CC Expiry'}))
    cvc = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'custom-input', 'placeholder': 'CVC'}))
    # is_subscribed = forms.BooleanField(required=False)

    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(attrs={'class': 'custom-input', 'placeholder': 'Password'})
    )
    password2 = forms.CharField(
        label='Confirm Password',
        widget=forms.PasswordInput(attrs={'class': 'custom-input', 'placeholder': 'Confirm Password'})
    )

    # TODO - add is_subscribed
    class Meta:
        model = CustomUser
        fields = ('email', 'username', 'first_name', 'last_name', 'password1', 'password2', 'phone', 'address', 'state', 'zip', 'cc_number', 'cc_name', 'cc_exp', 'cvc')
class UserProfileUpdateForm(UserChangeForm):
    password = None # exclude the password from the form
    class Meta:
        model = CustomUser
        fields = ('username', 'first_name', 'last_name', 'phone', 'address', 'state', 'zip', 'cc_num', 'cc_name', 'cc_expiry', 'cvc')
        widgets = {
            'address' : forms.Textarea(attrs={'rows': 1, 'cols': 40}),
        }
        def clean_email(self):
            return self.instance.email # treat it as property that cannot be changed.
