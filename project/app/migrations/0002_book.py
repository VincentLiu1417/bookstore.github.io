# Generated by Django 5.0.7 on 2024-07-18 18:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Book',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('isbn', models.CharField(max_length=13)),
                ('authors', models.CharField(max_length=255)),
                ('category', models.CharField(max_length=100)),
                ('title', models.CharField(max_length=255)),
                ('cover_picture', models.ImageField(upload_to='book_covers/')),
                ('edition', models.CharField(max_length=50)),
                ('pubisher', models.CharField(max_length=100)),
                ('publication_year', models.PositiveIntegerField()),
                ('quantity_in_stock', models.IntegerField()),
                ('minimum_threshold', models.IntegerField()),
                ('buying_price', models.DecimalField(decimal_places=2, max_digits=10)),
                ('selling_price', models.DecimalField(decimal_places=2, max_digits=10)),
            ],
        ),
    ]
