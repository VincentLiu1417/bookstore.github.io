from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, get_user_model
from django.contrib.auth.decorators import login_required, user_passes_test
from .forms import CustomUserCreationForm, UserProfileUpdateForm, CustomAuthenticationForm, CustomPasswordResetForm, BookForm, BookSearchForm
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.core.mail import send_mail, EmailMessage
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .tokens import account_activation_token
from .models import CustomUser, Book
from django.conf import settings
from django.contrib.auth.views import LoginView, PasswordResetConfirmView
from django.contrib.auth import logout
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import update_session_auth_hash
from django.contrib import messages
from django.contrib.auth.forms import PasswordResetForm
from django.urls import reverse_lazy
from django.contrib.auth.views import PasswordResetView, PasswordResetConfirmView
from django.db.models import Q
import random
from .utils import get_user_backend
User = get_user_model()

def home(request):
    featured_books = list(Book.objects.filter(category='featured'))
    new_arrivals_books = list(Book.objects.filter(category='new_arrivals'))

    featured_books = random.sample(featured_books, min(len(featured_books), 5))
    new_arrivals_books = random.sample(new_arrivals_books, min(len(new_arrivals_books), 5))

    context = {
        'featured_books' : featured_books,
        'new_arrivals_books': new_arrivals_books,
    }
    return render(request, 'home_template.html', context)

def book_list(request):
    form = BookSearchForm(request.GET or None)
    books = Book.objects.all()
    if form.is_valid():
        query = form.cleaned_data.get('query')
        if query:
            books = books.filter(
                Q(title__icontains=query) |
                Q(authors__icontains=query) |
                Q(isbn__icontains=query) |
                Q(category__icontains=query)
            )
        
    return render(request, 'book_list.html', {'books': books, 'form': form})

def book_detail(request, pk):
    book = get_object_or_404(Book, pk=pk)
    return render(request, 'book_detail.html', {'book': book})

@login_required(login_url='/login/')
def add_to_cart(request, book_id):
    messages.success(request, "Added to cart!")
    return redirect(reverse('book_detail', args=[book_id]))

@login_required(login_url='/login/')
def view_cart(request):
    return render(request, 'view_cart.html')

def user_is_admin(user):
    return user.is_admin

@login_required
@user_passes_test(user_is_admin)
def add_book(request):
    if request.method == 'POST':
        form = BookForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('book_list')
    else:
        form = BookForm()
    return render(request, 'add_book.html', {'form': form})
        

def custom_password_reset(request):
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            associated_users = User.objects.filter(email=email)
            if associated_users.exists():
                for user in associated_users:
                    subject = 'Password Reset Request'
                    email_template_name = 'registration/password_reset_email.html'
                    c = {
                        'email': user.email,
                        'domain': request.META['HTTP_HOST'],
                        'site_name': settings.SITE_NAME,
                        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                        'user':user,
                        'token': default_token_generator.make_token(user),
                        'protocol':'http',
                    }
                email_content = render_to_string(email_template_name, c)
                send_mail(subject, email_content, settings.DEFAULT_FROM_EMAIL, [user.email])
            messages.success(request, 'Password reset email has been sent. Please check your email.')
            return redirect('password_reset_done')
        else:
            messages.error(request, "No account found with that email.")
    else:
        form = PasswordResetForm()
    return render(request, 'registration/password_reset_form.html', {'form': form})

def custom_password_reset_confirm(request, uidb64=None, token=None):
    '''
    Checks the hash in a password reset link and presents a form for entering a new PW
    '''
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = SetPasswordForm(user, request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, 'Your password has been reset.')
                return redirect('password_reset_complete')
        else:
            form = SetPasswordForm(user)
        return render(request, 'registration/password_reset_confirm.html', {'form':form, 'uidb64':uidb64, 'token':token})
    else:
        messages.error(request, 'The password reset link is invalid or has expired. Please try again.')
        return redirect('password_reset_done')

    
'''
def custom_password_reset_sent(request):
    return render(request, 'registration/password_reset_sent.html')

def custom_password_reset_request(request):
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            user_email = form.cleaned_data['email']
            associated_users = User.objects.filter(email=user_email)
            if associated_users.exists():
                for user in associated_users:
                    subject = "Password Reset Requested"
                    email_template_name = "registration/password_reset_email.html"
                    c = {
                        "email": user.email,
                        'domain': request.META['HTTP_HOST'],
                        'site_name': 'Your Site',
                        "user": user,
                        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                        'token': default_token_generator.make_token(user),
                        'protocol': 'http',
                    }
                    email = render_to_string(email_template_name, c)
                    try:
                        email_message = EmailMessage(subject, email, settings.EMAIL_HOST_USER, [user.email])
                        email_message.send()
                    except Exception as e:
                        messages.error(request, f'An error occurred: {e}')
                        return render(request, "registration/password_reset.html", {"form": form})
                    messages.success(request, f'An email has been sent to {user_email}. Please check its inbox to continue resetting password.')
                    return redirect('password_reset_sent')
            else:
                messages.error(request, 'No user is associated with this email')
                return render(request, "registration/password_reset.html", {"form": form})
        else:
            return render(request, "registration/password_reset.html", {"form": form})
    else:
        form = PasswordResetForm()
    return render(request, "registration/password_reset.html", {"form": form})



def custom_password_reset_confirm(request, uidb64, token):
    try:
        uid = force_str(uslsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = SetPasswordForm(user, request.POST)
            if form.is_valid():
                form.save()
                update_session_auth_hash(request, user) # maintaining user session
                messages.success(request, 'Your password has been reset.')
                return redirect('/') # consider changing this to 'profile/'
            else:
                messages.error(request, 'Please correct the error below.')
        else:
            form = SetPasswordForm(user)
        return render(request, 'registration/password_reset_confirm.html', {'form': form})
    else:
        messages.error(request, 'The reset password link is invalid or has expired. Please try again.')
        return redirect('password_reset') # make sure that this is the correct url...pretty sure it should be password_change
  '''                     

def custom_logout_view(request):
    logout(request)
    return redirect('/')


def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_verified = True
        user.save()
        backend = get_user_backend(user)
        if backend:
            login(request, user, backend=backend)
        return redirect('home')
    else:
        return render(request, 'registration/activation_invalid.html')


def send_verification_email(request, user):
    current_site = get_current_site(request)
    mail_subject = 'Activate your account.'
    message = render_to_string('registration/account_activation_email.html', {
        'user': user,
        'domain': current_site.domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': account_activation_token.make_token(user)
    })

    to_email = user.email
    send_mail(mail_subject, message, settings.DEFAULT_FROM_EMAIL, [to_email])

def email_verification_sent(request):
    return render(request, 'registration/email_verification_sent.html')
    
def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_verified = False
            user.save()
            # verification email -- implement
            send_verification_email(request, user)
            return redirect('email_verification_sent')
    else:
        form = CustomUserCreationForm()
    return render(request, 'registration/register.html', {'form': form})


@login_required
def profile_update(request):
    if request.method == 'POST':
        form = UserProfileUpdateForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            return redirect('profile') # you need to design the profile page
    else:
        form = UserProfileUpdateForm(instance=request.user)
    return render(request, 'registration/profile_update.html', {'form': form})
            
@login_required
def profile(request):
    return render(request, 'registration/profile.html', {'user': request.user})

@login_required
def change_password(request):
    '''
    Will be used to implement the change_password use case.
    '''
    pass

@login_required
def payment_methods(request):
    '''
    Will be used to implement the change payment methods use case.
    '''
    pass

class CustomLoginView(LoginView):
    authentication_form = CustomAuthenticationForm
    template_name = 'registration/login.html'
'''
class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    form_class = CustomSetPasswordForm
    template_name = 'registration/password_reset_confirm.html'

class CustomPasswordResetView(PasswordResetView):
    form_class = CustomPasswordResetForm
    template_name = 'registration/password_reset_form.html'
    success_url = reverse_lazy('password_reset_done')
    email_template_name = 'registration/password_reset_email.html'
    subject_template_name = 'registration/password_reset_subject.txt'
class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'registration/password_reset_confirm.html'
    success_url = reverse_lazy('password_reset_complete')
'''
