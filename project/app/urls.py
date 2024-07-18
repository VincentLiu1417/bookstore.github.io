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
    path('books/<int:pk>/', views.book_detail, name='book_detail')
]
'''
    path('profile/password_reset/', views.custom_password_reset_request, name='password_reset')
 
    path('profile/password_reset/sent', views.custom_password_reset_sent, name='password_reset_sent'),
    path('profile/password_reset/<uidb64>/<token>/', views.CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('profile/password_reset/', CustomPasswordResetView.as_view(), name='password_reset'),
    '''
