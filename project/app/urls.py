from django.urls import path
from . import views
from django.contrib.auth.views import LogoutView
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('email_verification_sent/', views.email_verification_sent, name='email_verification_sent'),
    path('', views.home, name='home'),
    path('profile/', views.profile, name='profile'),
    path('profile/update', views.profile_update, name='profile_update'),
    #path('profile/change_password', views.change_password, name='password_change'),
    path('profile/payment_methods', views.payment_methods, name='profile_payment_methods'),
    path('login/', views.CustomLoginView.as_view(), name='login'),
#    path('logout/', LogoutView.as_view(next_page='/'), name='logout')
    path('logout/', views.custom_logout_view, name='logout'),

    path('reset-password', views.custom_password_reset, name='custom_password_reset'),
    path('reset-password/done/', auth_views.PasswordResetDoneView.as_view(template_name='registration/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', views.custom_password_reset_confirm, name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='registration/password_reset_complete.html'), name='password_reset_complete'),
    
    path('add_book/', views.add_book, name='add_book'),
    path('books/', views.book_list, name='book_list'),
    path('books/<int:pk>/', views.book_detail, name='book_detail'),
    path('add_to_cart/<int:book_id>/', views.add_to_cart, name='add_to_cart'),
    path('view_cart/', views.view_cart, name='view_cart'),
    path('cart/update/<int:item_id>/', views.update_cart_item, name='update_cart_item'),
    path('cart/delete/<int:item_id>/', views.delete_cart_item, name='delete_cart_item'),
    path('checkout_test/', views.checkout_test, name='checkout_test'),
    path('apply_promotion/', views.apply_promotion, name='apply_promotion'),
    path('order_confirmation/<str:order_number>/', views.order_confirmation, name='order_confirmation'),

    path('admin_home/', views.admin_home, name='admin_home'),
    path('admin_manage_book/', views.admin_manage_book, name='admin_manage_book'),
    path('admin_promotions/', views.admin_promotions, name='admin_promotions'),
    path('admin_view_user_book/', views.admin_view_user_book, name='admin_view_user_book'),
    
    path('book_detail/', views.book_detail, name='book_detail'),
    path('buy_again/', views.buy_again, name='buy_again'),
    path('index/', views.index, name='index'),
    path('login_test/', views.login_test, name='login_test'),
    path('membership/', views.membership, name='membership'),
    path('order_history/', views.order_history, name='order_history'),
    path('payment_info/', views.payment_info, name='payment_info'),
    path('registration_test/', views.registration_test, name='registration_test'),
    path('search_test/', views.search_test, name='search_test'),
    path('shipping_address/', views.shipping_address, name='shipping_address'),
    path('update_shipping_info/', views.update_shipping_info, name='update_shipping_info'),
    path('add_delivery_instructions/', views.add_delivery_instructions, name='add_delivery_instructions'),
    path('update_payment_info/', views.update_payment_info, name='update_payment_info'),
]
'''
    path('profile/password_reset/', views.custom_password_reset_request, name='password_reset')
 
    path('profile/password_reset/sent', views.custom_password_reset_sent, name='password_reset_sent'),
    path('profile/password_reset/<uidb64>/<token>/', views.CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('profile/password_reset/', CustomPasswordResetView.as_view(), name='password_reset'),
    '''
