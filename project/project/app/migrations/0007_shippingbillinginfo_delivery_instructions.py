# Generated by Django 4.2.14 on 2024-07-28 22:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0006_cart_promotion_shippingbillinginfo_paymentinfo_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='shippingbillinginfo',
            name='delivery_instructions',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]
