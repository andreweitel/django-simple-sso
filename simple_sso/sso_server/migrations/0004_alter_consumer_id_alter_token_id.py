# Generated by Django 4.0.1 on 2022-02-21 22:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sso_server', '0003_token_session'),
    ]

    operations = [
        migrations.AlterField(
            model_name='consumer',
            name='id',
            field=models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
        migrations.AlterField(
            model_name='token',
            name='id',
            field=models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
    ]
