import string
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, get_user_model
from django.contrib.auth.decorators import login_required, user_passes_test
from .forms import CustomUserCreationForm, UserProfileUpdateForm, CustomAuthenticationForm, CustomPasswordResetForm, BookForm, BookSearchForm, PaymentInfoForm, ShippingBillingForm, PaymentForm, PromotionFactoryForm
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.core.mail import send_mail, EmailMessage
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .tokens import account_activation_token
from .models import CustomUser, Book, PaymentInfo, ShippingBillingInfo, Promotion, CartItem, Cart
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
from decimal import Decimal
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

def fiction(request):
    books = Book.objects.all().filter(Q(category__icontains='fiction'))
    return render(request, 'book_list.html', {'books': books})

def nonfiction(request):
    books = Book.objects.all().filter(Q(category__icontains='nonfiction'))
    return render(request, 'book_list.html', {'books': books})

def teen(request):
    books = Book.objects.all().filter(Q(category__icontains='teen'))
    return render(request, 'book_list.html', {'books': books})

def kids(request):
    books = Book.objects.all().filter(Q(category__icontains='kids'))
    return render(request, 'book_list.html', {'books': books})

def classics(request):
    books = Book.objects.all().filter(Q(category__icontains='classics'))
    return render(request, 'book_list.html', {'books': books})

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

def user_is_admin(user):
    return user.is_admin

'''
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
#            messages.success(request, 'Shipping information updated successfully!')
            return redirect('view_cart')
    else:
        form = ShippingBillingForm(instance=shipping_info)

    return render(request, 'update_shipping_info.html', {'form': form})

'''
"""
@login_required
@user_passes_test(user_is_admin)
def manage_book(request, pk):
    if request.method == 'POST':
        form = BookForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('book_list')
        else:
            form = BookForm()
        return render(request, )
"""
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
        user_form = CustomUserCreationForm(request.POST)
        payment_form = PaymentInfoForm(request.POST)
        
        if user_form.is_valid():
            user = user_form.save(commit=False)
            user.is_verified = False
            user.save()
            # verification email -- implement
            send_verification_email(request, user)
            if payment_form.is_valid():
                payment_info = payment_form.save(commit=False)
                payment_info.user = user
                payment_info.save()
            return redirect('email_verification_sent')
        
    else:
        user_form = CustomUserCreationForm()
        payment_form = PaymentInfoForm()
    return render(request, 'registration/register.html', {'user_form': user_form,
                                                          'payment_form': payment_form})


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


class CustomLoginView(LoginView):
    authentication_form = CustomAuthenticationForm
    template_name = 'registration/login.html'

@login_required
def payment_info_list(request):
    #payment_methods = request.user.payment_methods.all()
    payment_info = PaymentInfo.objects.filter(user=request.user)
    context = {
        'payment_methods': payment_info,
    }
    return render(request, 'payment_info_list.html',context)

@login_required
def add_payment_info(request):
    if request.method == 'POST':
        form = PaymentInfoForm(request.POST)
        if form.is_valid():
            #payment_info = form.save(commit=False)
            #payment_info.user = request.user
            #payment_info.save()
            #messages.success(request, 'Payment method added successfully.')
            form.save(user=request.user)
            return redirect('payment_info_list')
    else:
        form = PaymentInfoForm()
    return render(request, 'add_payment_info.html', {'form': form})


@login_required
def update_payment_info_nopk(request):
    try:
        payment_info = PaymentInfo.objects.filter(user=request.user)
    except PaymentInfo.DoesNotExist:
        payment_info = None

    if request.method == 'POST':
        form = PaymentForm(request.POST, instance=payment_info)
        if form.is_valid():
            payment_info = form.save(commit=False)
            payment_info.user = request.user
            payment_info.save()
            messages.success(request, 'Payment information updated successfully!')
            return redirect('view_cart')
    else:
        form = PaymentForm(instance=payment_info)

    return render(request, 'update_payment_info.html', {'form': form})

@login_required
def update_payment_method(request):
    payment_infos = PaymentInfo.objects.filter(user=request.user)
    if request.method == 'POST':
        form = PaymentInfoForm(request.POST)
        if form.is_valid():
            new_payment_info = form.save(commit=False)
            new_payment_info.user = request.user
            new_payment_info.save()
            return redirect('update_payment_method')
    else:
        form = PaymentInfoForm()
    context = {
        'payment_infos': payment_infos,
        'form': form,
    }
    return render(request, 'update_payment_method.html', context)

@login_required
# views.py
def select_payment_method_view(request, payment_info_id):
    try:
        selected_payment_info = PaymentInfo.objects.get(id=payment_info_id, user=request.user)
        request.session['payment_info_id'] = selected_payment_info.id
    except PaymentInfo.DoesNotExist:
        redirect('update_payment_method')  # Handle error if payment info does not exist

    return redirect('checkout_test')

@login_required
def checkout_view(request):
    user = request.user

    # Fetch user's shipping and payment info
    saved_shipping = ShippingBillingInfo.objects.filter(user=user).first()
    saved_cards = PaymentInfo.objects.filter(user=user)
    decrypted_payment_info = None

    if saved_cards.exists():
        last_card = saved_cards.last()
        decrypted_payment_info = {
            'card_number': last_card.get_decrypted_card_number(),
            'expiration_date': last_card.get_decrypted_expiration_date(),
            'cvv': last_card.get_decrypted_cvv()
        }

    if request.method == 'POST':
        payment_form = PaymentForm(request.POST)
        shipping_form = ShippingBillingForm(request.POST)

        if payment_form.is_valid() and shipping_form.is_valid():
            # Handle payment information encryption
            card_number = PaymentInfo.encrypt_value(payment_form.cleaned_data['card_number'])
            expiration_date = PaymentInfo.encrypt_value(payment_form.cleaned_data['expiration_date'])
            cvv = PaymentInfo.encrypt_value(payment_form.cleaned_data['cvv'])

            PaymentInfo.objects.update_or_create(
                user=user,
                defaults={
                    'card_number': card_number,
                    'expiration_date': expiration_date,
                    'cvv': cvv
                }
            )

            # Handle shipping information
            shipping_info = shipping_form.save(commit=False)
            shipping_info.user = user
            shipping_info.save()

            return redirect('checkout_success')

    else:
        payment_form = PaymentForm()
        shipping_form = ShippingBillingForm()

    context = {
        'saved_shipping': saved_shipping,
        'saved_cards': saved_cards,
        'payment_form': payment_form,
        'shipping_form': shipping_form,
        'decrypted_payment_info': decrypted_payment_info,
    }

    return render(request, 'checkout_test.html', context)


@login_required
def update_payment_info(request, pk):
    payment_info = get_object_or_404(PaymentInfo, pk=pk, user=request.user)
    if request.method == 'POST':
        form = PaymentInfoForm(request.POST, instance=payment_info)
        if form.is_valid():
            form.save()
            #messages.success(request, 'Payment method updated successfully.')
            return redirect('payment_info_list')
    else:
        form = PaymentInfoForm(instance=payment_info)
    return render(request, 'update_payment_info.html', {'form': form})

@login_required
def delete_payment_info(request, pk):
    payment_info = get_object_or_404(PaymentInfo, pk=pk, user=request.user)
    if request.method == 'POST':
        payment_info.delete()
#        messages.success(request, 'Payment method deleted successfully.')
        return redirect('payment_info_list')
    return render(request, 'delete_payment_info.html', {'payment_info': payment_info})

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
#            messages.success(request, 'Shipping information updated successfully!')
            return redirect('view_cart')
    else:
        form = ShippingBillingForm(instance=shipping_info)

    return render(request, 'update_shipping_info.html', {'form': form})




@login_required
def checkout_test(request):
    print("checkout_test invoked")
    cart = Cart.objects.get(user=request.user)
    saved_cards = PaymentInfo.objects.filter(user=request.user)
    saved_shipping = ShippingBillingInfo.objects.filter(user=request.user).first()

    TAX_RATE = Decimal('0.08')
    SHIPPING_HANDLING_FEE = Decimal('5.00')
    print('tax rt calculated')
    if request.method == 'POST':
        print('request was post')
        shipping_billing_form = ShippingBillingForm(request.POST, instance=saved_shipping)
        payment_form = PaymentForm(request.POST)
        print('sbf and pf loaded')
        if shipping_billing_form.is_valid() and payment_form.is_valid():
            print('form is valid')
            shipping_billing_info = shipping_billing_form.save(commit=False)
            shipping_billing_info.user = request.user
            shipping_billing_info.save()
            payment_info = payment_form.save(commit=False)
            payment_info.user = request.user
            payment_info.save()
            print('saved pmt info')
            order_number = ''.join(random.choices(string.digits, k=12))
            date_ordered = datetime.now().strftime("%m/%d/%Y")
            total_price = sum(item.book.selling_price * item.quantity for item in cart.cartitem_set.all())
            tax = total_price * TAX_RATE
            order_total = total_price + tax + SHIPPING_HANDLING_FEE
            payment_info_id = request.POST.get('payment_info_id')
            print('order info put together, about to get card')
            card = None
            if payment_info_id:
                card = PaymentInfo.objects.get(id=payment_info_id)
                print('card snatched from context')
            else:
                card = saved_cards.last() if saved_cards.exists() else None
                print('card is last')
            print('creating object')
            order = Order.objects.create(
                user=request.user,
                order_number=order_number,
                total_price=total_price,
                tax=tax,
                shipping_fee=SHIPPING_HANDLING_FEE,
                order_total=order_total,
                shipping_info=saved_shipping,
                payment_info=card,
            )
            print('order created')

            for item in cart.cartitem_set.all():
                OrderItem.objects.create(
                    order=order,
                    book=item.book,
                    quantity=item.quantity
                )
            print('items created')
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
            print('order data saved')
            request.session['order_data'] = order_data
            print('redirecting to order_confirmation')
            return redirect('order_confirmation', order_number=order.order_number)

            #messages.success(request, 'Checkout information successfully saved!')
            #return redirect('order_confirmation')
        else:
            # Print form errors for debugging
            if not shipping_billing_form.is_valid():
                print('Shipping Billing Form errors:', shipping_billing_form.errors)
            if not payment_form.is_valid():
                print('Payment Form errors:', payment_form.errors)
    else:
        shipping_billing_form = ShippingBillingForm()
        payment_form = PaymentForm()

    total_price = sum(item.book.selling_price * item.quantity for item in cart.cartitem_set.all())
    selected_payment_info = None
    if 'payment_info_id' in request.session:
        try:
            selected_payment_info = PaymentInfo.objects.get(id=request.session['payment_info_id'])
        except PaymentInfo.DoesNotExist:
            pass
    if not selected_payment_info:
        if saved_cards.exists():
            selected_payment_info = saved_cards.last()
    return render(request, 'checkout_test.html', {
        'cart': cart,
        'shipping_billing_form': shipping_billing_form,
        'payment_form': payment_form,
        'saved_cards': saved_cards,
        'saved_shipping': saved_shipping,
        'total_price': total_price,
        'selected_payment_info':selected_payment_info,
    })

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
def order_confirmation(request):
    cart = Cart.objects.get(user=request.user)
    cart_items = CartItem.objects.filter(cart=cart)
    return render(request, 'order_confirmation.html', {'cart': cart, 'cart_items': cart_items})

@login_required
@user_passes_test(user_is_admin)
def create_promotion(request):
    '''
    Works with forms.PromotionFactoryForm to create promotions and email them to users.
    '''
    if request.method == 'POST':
        form = PromotionFactoryForm(request.POST)
        if form.is_valid():
            promotion = form.save()

            # sending the promos to subscribed users.
            subscribed_users = CustomUser.objects.filter(is_subscribed=True)
            for user in subscribed_users:
                send_mail(
                    'New Promotion Available',
                    f'Hi {user.first_name}, \n\nUse the code {promotion.code} for {promotion.discount} off your next purchase from team3books.\n\nBest, team3books',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                )
            return redirect('promotion_success') # redirects to success page
    else:
        form = PromotionFactoryForm()
    return render(request, 'create_promotion.html', {'form': form})

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
@user_passes_test(user_is_admin)
def promotion_success(request):
    return render(request, 'promotion_success.html')

def custom_error_view(request, exception=None, template_name='500.html'):
    '''
    Returns the custom error template.
    '''
    return render(request, template_name)
