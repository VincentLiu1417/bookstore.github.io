from django.urls import path
from . import views
from django.contrib.auth.views import LogoutView
from django.contrib.auth import views as auth_views
from django.conf.urls import handler400, handler403, handler404, handler500
urlpatterns = [
    path('update_payment/', views.update_payment_method, name='update_payment_method'),
    path('select-payment-method/<int:payment_info_id>/', views.select_payment_method_view, name='select_payment_method'),
    path('add_delivery_instructions/', views.add_delivery_instructions, name='add_delivery_instructions'),
    path('register/', views.register, name='register'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('email_verification_sent/', views.email_verification_sent, name='email_verification_sent'),
    path('', views.home, name='home'),
    path('profile/', views.profile, name='profile'),
    path('profile/update', views.profile_update, name='profile_update'),
    #path('profile/change_password', views.change_password, name='password_change'),
    path('profile/payment_methods/', views.payment_info_list, name='payment_info_list'),
    path('profile/payment_methods/add/', views.add_payment_info, name='add_payment_info'),
    path('profile/payment_methods/update/<int:pk>/', views.update_payment_info, name='update_payment_info'),
    path('cart/payment_method/update/', views.update_payment_info_nopk, name='update_payment_info_nopk'),
    path('profile/payment_methods/delete/<int:pk>/', views.delete_payment_info, name='delete_payment_info'),
    path('login/', views.CustomLoginView.as_view(), name='login_page'),
#    path('logout/', LogoutView.as_view(next_page='/'), name='logout')
    path('logout/', views.custom_logout_view, name='logout'),

    path('classics/', views.classics, name='classics'),
    path('kids/', views.kids, name='kids'),
    path('teen/', views.teen, name='teen'),
    path('fiction', views.fiction, name='fiction'),
    path('nonfiction', views.nonfiction, name='nonfiction'),
    
    path('reset-password', views.custom_password_reset, name='custom_password_reset'),
    path('reset-password/done/', auth_views.PasswordResetDoneView.as_view(template_name='registration/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', views.custom_password_reset_confirm, name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='registration/password_reset_complete.html'), name='password_reset_complete'),
    path('add_book/', views.add_book, name='add_book'),
    path('books/', views.book_list, name='book_list'),
    path('books/<int:pk>/', views.book_detail, name='book_detail'),
    path('add_to_cart/<int:book_id>/', views.add_to_cart, name='add_to_cart'),
    path('cart/', views.view_cart, name='view_cart'),
    path('create-promotion/', views.create_promotion, name='create_promotion'),
    path('promotion-success/', views.promotion_success, name='promotion_success'),
    

### Nancy's URLS ###
    path('add_to_cart/<int:book_id>/', views.add_to_cart, name='add_to_cart'),
    path('view_cart/', views.view_cart, name='view_cart'),
    path('cart/update/<int:item_id>/', views.update_cart_item, name='update_cart_item'),
    path('cart/delete/<int:item_id>/', views.delete_cart_item, name='delete_cart_item'),
    path('checkout_test/', views.checkout_test, name='checkout_test'),
    path('apply_promotion/', views.apply_promotion, name='apply_promotion'),
    path('order_confirmation/', views.order_confirmation, name='order_confirmation'),
    path('update_shipping_info/', views.update_shipping_info, name='update_shipping_info'),
   # path('admin_home/', views.admin_home, name='admin_home'),

    #path('admin_manage_book/', views.admin_manage_book, name='admin_manage_book'),
    #path('admin_promotions/', views.admin_promotions, name='admin_promotions'),
    #path('admin_view_user_book/', views.admin_view_user_book, name='admin_view_user_book'),

    #path('book_detail/', views.book_detail, name='book_detail'),
    #path('buy_again/', views.buy_again, name='buy_again'),
    
    
]

handler400 = lambda request, exception=None: views.custom_error_view(request, exception, '400.html')
#handler401 = lambda request, exception=None: views.custom_error_view(request, exception, '401.html')
handler403 = lambda request, exception=None: views.custom_error_view(request, exception, '403.html')
handler404 = lambda request, exception=None: views.custom_error_view(request, exception, '404.html')
#handler405 = lambda request, exception=None: views.custom_error_view(request, exception, '405.html')
#handler408 = lambda request, exception=None: views.custom_error_view(request, exception, '408.html')
#handler409 = lambda request, exception=None: views.custom_error_view(request, exception, '409.html')
#handler410 = lambda request, exception=None: views.custom_error_view(request, exception, '410.html')
handler500 = lambda request, exception=None: views.custom_error_view(request, exception, '500.html')
#handler501 = lambda request, exception=None: views.custom_error_view(request, exception, '501.html')
#handler502 = lambda request, exception=None: views.custom_error_view(request, exception, '502.html')
#handler503 = lambda request, exception=None: views.custom_error_view(request, exception, '503.html')
#handler504 = lambda request, exception=None: views.custom_error_view(request, exception, '504.html')
#handler505 = lambda request, exception=None: views.custom_error_view(request, exception, '505.html')
