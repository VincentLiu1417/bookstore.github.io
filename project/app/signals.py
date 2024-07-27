from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.core.exceptions import ValidationError
from .models import PaymentInfo

@receiver(pre_save, sender=PaymentInfo)
def validate_payment_methods_limit(sender, instance, **kwargs):
    if instance.user.payment_methods.count() >= 3 and not instance.pk:
        raise ValidationError('A user cannot have more than 3 payment methods.')
