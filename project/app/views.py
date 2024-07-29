from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, get_user_model
from django.contrib.auth.decorators import login_required, user_passes_test
from .forms import CustomUserCreationForm, UserProfileUpdateForm, CustomAuthenticationForm, CustomPasswordResetForm, BookForm, BookSearchForm, ShippingBillingForm, PaymentForm, PromotionCodeForm
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.core.mail import send_mail, EmailMessage
from django.template.loader import render_to_string
from django.http import JsonResponse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .tokens import account_activation_token
from .models import CustomUser, Book, Cart, CartItem, Promotion, ShippingBillingInfo, PaymentInfo, Order, OrderItem
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
from .utils import get_user_backend
from decimal import Decimal
from datetime import datetime
import random
import string

User = get_user_model()

def home(request):
    # Fetch featured and new arrivals books
    featured_books = list(Book.objects.filter(category='featured'))
    new_arrivals_books = list(Book.objects.filter(category='new_arrivals'))

    # Randomly select up to 5 books from each category
    featured_books = random.sample(featured_books, min(len(featured_books), 5))
    new_arrivals_books = random.sample(new_arrivals_books, min(len(new_arrivals_books), 5))

    # Get cart items for the authenticated user
    if request.user.is_authenticated:
        cart_items = CartItem.objects.filter(cart__user=request.user)
    else:
        cart_items = []

    context = {
        'featured_books' : featured_books,
        'new_arrivals_books': new_arrivals_books,
        'cart_items': cart_items,
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
def email_confirmation(request):
    return render(request, 'app/emailConfirmation.html')

@login_required
def view_cart(request):
    try:
        cart = Cart.objects.get(user=request.user)
    except Cart.DoesNotExist:
        cart = Cart.objects.create(user=request.user)
    cart_items = CartItem.objects.filter(cart=cart)
    total_price = sum(item.book.selling_price * item.quantity for item in cart_items)
    return render(request, 'view_cart.html', {
        'cart': cart,
        'cart_items': cart_items,
        'total_price': total_price,
    })

@login_required
def add_to_cart(request, book_id):
    book = get_object_or_404(Book, id=book_id)
    cart, created = Cart.objects.get_or_create(user=request.user)
    cart_item, created = CartItem.objects.get_or_create(cart=cart, book=book, defaults={'quantity': 1})

    if not created:
        cart_item.quantity += 1
        cart_item.save()
    messages.success(request, 'Book added to cart')
    return redirect('view_cart')

@login_required
def update_cart_item(request, item_id):
    cart_item = get_object_or_404(CartItem, id=item_id, cart__user=request.user)
    if request.method == 'POST':
        quantity = int(request.POST.get('quantity', 1))
        if quantity > 0:
            cart_item.quantity = quantity
            cart_item.save()
        else:
            cart_item.delete()
    return redirect('view_cart')

@login_required
def delete_cart_item(request, item_id):
    item = get_object_or_404(CartItem, id=item_id, cart__user=request.user)
    item.delete()
    return redirect('view_cart')

@login_required
def update_shipping_info(request):
    try:
        shipping_info = ShippingBillingInfo.objects.get(user=request.user)
    except ShippingBillingInfo.DoesNotExist:
        shipping_info = None

    if request.method == 'POST':
        form = ShippingBillingForm(request.POST, instance=shipping_info)
        if form.is_valid():
            shipping_info = form.save(commit=False)
            shipping_info.user = request.user
            shipping_info.save()
            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({'success': True})
            messages.success(request, 'Shipping information updated successfully!')
            return redirect('checkout_test')
        else:
            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'errors': form.errors.as_json()})
    else:
        form = ShippingBillingForm(instance=shipping_info)

    return render(request, 'update_shipping_info.html', {'form': form})

@login_required
def update_payment_info(request):
    try:
        payment_info = PaymentInfo.objects.get(user=request.user)
    except PaymentInfo.DoesNotExist:
        payment_info = None

    if request.method == 'POST':
        form = PaymentForm(request.POST, instance=payment_info)
        if form.is_valid():
            payment_info = form.save(commit=False)
            payment_info.user = request.user
            payment_info.save()
            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({'success': True})
            messages.success(request, 'Payment information updated successfully!')
            return redirect('checkout_test')
        else:
            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'errors': form.errors.as_json()})
    else:
        form = PaymentForm(instance=payment_info)

    return render(request, 'update_payment_info.html', {'form': form})

@login_required
def add_delivery_instructions(request):
    if request.method == 'POST':
        instructions = request.POST.get('instructions', '')
        try:
            shipping_info = ShippingBillingInfo.objects.get(user=request.user)
            shipping_info.delivery_instructions = instructions
            shipping_info.save()
            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({'success': True, 'instructions': instructions})
            messages.success(request, 'Delivery instructions added successfully!')
        except ShippingBillingInfo.DoesNotExist:
            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'errors': 'No shipping information found.'})
            messages.error(request, 'No shipping information found. Please update your shipping information first.')
    return redirect('checkout_test')

@login_required
def checkout_test(request):
    cart = Cart.objects.get(user=request.user)
    saved_cards = PaymentInfo.objects.filter(user=request.user)
    saved_shipping = ShippingBillingInfo.objects.filter(user=request.user).first()

    TAX_RATE = Decimal('0.08')
    SHIPPING_HANDLING_FEE = Decimal('5.00')

    if request.method == 'POST':
        shipping_billing_form = ShippingBillingForm(request.POST)
        payment_form = PaymentForm(request.POST)
        if shipping_billing_form.is_valid() and payment_form.is_valid():
            shipping_billing_info = shipping_billing_form.save(commit=False)
            shipping_billing_info.user = request.user
            shipping_billing_info.save()
            payment_info = payment_form.save(commit=False)
            payment_info.user = request.user
            payment_info.save()

            order_number = ''.join(random.choices(string.digits, k=12))
            date_ordered = datetime.now().strftime("%m/%d/%Y")

            total_price = sum(item.book.selling_price * item.quantity for item in cart.cartitem_set.all())
            tax = total_price * TAX_RATE
            order_total = total_price + tax + SHIPPING_HANDLING_FEE

            order = Order.objects.create(
                user=request.user,
                order_number=order_number,
                total_price=total_price,
                tax=tax,
                shipping_fee=SHIPPING_HANDLING_FEE,
                order_total=order_total,
                shipping_info=saved_shipping,
                payment_info=saved_cards.last()
            )

            for item in cart.cartitem_set.all():
                OrderItem.objects.create(
                    order=order,
                    book=item.book,
                    quantity=item.quantity
                )

            order_data = {
                'order_number': order.order_number,
                'date_ordered': date_ordered,
                'total': order.order_total,
                'shipping_info': order.shipping_info,
                'payment_info': order.payment_info,
                'cart_items': cart.cartitem_set.all(),
                'total_price': total_price,
                'tax': tax,
                'shipping': SHIPPING_HANDLING_FEE,
                'order_total': order_total,
            }

            request.session['order_data'] = order_data
            return redirect('order_confirmation', order_number=order.order_number)

    else:
        shipping_billing_form = ShippingBillingForm()
        payment_form = PaymentForm()

    total_price = sum(item.book.selling_price * item.quantity for item in cart.cartitem_set.all())
    tax = total_price * TAX_RATE
    order_total = total_price + tax + SHIPPING_HANDLING_FEE

    return render(request, 'checkout_test.html', {
        'cart': cart,
        'shipping_billing_form': shipping_billing_form,
        'payment_form': payment_form,
        'saved_cards': saved_cards,
        'saved_shipping': saved_shipping,
        'total_price': total_price,
        'tax': tax,
        'shipping': SHIPPING_HANDLING_FEE,
        'order_total': order_total,
    })

@login_required
def apply_promotion(request):
    if request.method == 'POST':
        form = PromotionCodeForm(request.POST)
        if form.is_valid():
            promotion_code = form.cleaned_data['code']
            try:
                promotion = Promotion.objects.get(code=promotion_code, is_active=True)
                request.user.cart.apply_promotion(promotion)
                messages.success(request, 'Promotion code applied successfully!')
            except Promotion.DoesNotExist:
                messages.error(request, 'Invalid promotion code.')
    return redirect('view_cart')

@login_required
def order_confirmation(request, order_number):
    order_data = request.session.get('order_data')
    if not order_data or order_data.get('order_number') != order_number:
        return redirect('checkout_test')

    email_subject = 'Your Order Confirmation'
    email_body = render_to_string('order_confirmation_email.html', order_data)
    send_mail(
        email_subject,
        email_body,
        'team3books@gmail.com',
        [request.user.email],
        fail_silently=False,
    )

    return render(request, 'order_confirmation.html', order_data)

def admin_home(request):
    return render(request, 'adminHomeTest.html')

def admin_manage_book(request):
    return render(request, 'adminManagebookTest.html')

def admin_promotions(request):
    return render(request, 'adminPromotions.html')

def admin_view_user_book(request):
    return render(request, 'adminViewUserbook.html')

def buy_again(request):
    return render(request, 'buyAgainTest.html')

def index(request):
    return render(request, 'index.html')

def login_test(request):
    return render(request, 'loginTest.html')

def membership(request):
    return render(request, 'membership.html')

def order_history(request):
    return render(request, 'orderHistoryTest.html')

def payment_info(request):
    return render(request, 'paymentInfo.html')

def registration_test(request):
    return render(request, 'registrationTest.html')

def search_test(request):
    return render(request, 'searchTest.html')

def shipping_address(request):
    return render(request, 'shippingAddress.html')