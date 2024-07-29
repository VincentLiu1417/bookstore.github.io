from django.contrib import admin
from .models import CustomUser, Book
from .forms import CustomUserCreationForm
from django.contrib.auth.admin import UserAdmin
# Register your models here.

admin.site.site_header = 'team3books'
admin.site.site_title = 'team3books'

class BookAdmin(admin.ModelAdmin):
    list_display = ('title', 'isbn', 'category', 'authors', 'publisher', 'publication_year', 'quantity_in_stock', 'buying_price', 'selling_price')
    search_fields = ('title', 'isbn', 'authors', 'publisher')
    list_filter = ('category', 'publication_year')

class CustomUserAdmin(UserAdmin):
    add_form = CustomUserCreationForm
    model = CustomUser
    list_display = ('email', 'username', 'first_name', 'last_name', 'is_admin', 'is_verified', 'is_suspended')
    list_filter = ('is_admin', 'is_verified', 'is_suspended')
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('username', 'first_name', 'last_name', 'phone', 'address', 'city', 'state', 'zip')}),
        ('Permissions', {'fields': ('is_admin', 'is_verified', 'is_suspended', 'is_superuser', 'groups', 'user_permissions')})
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'first_name', 'last_name', 'password1', 'password2', 'is_admin', 'is_verified', 'is_suspended', 'is_superuser')
        }),
    )
    search_fields = ('email', 'username', 'first_name', 'last_name')
    ordering = ('email',)

admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Book, BookAdmin)
