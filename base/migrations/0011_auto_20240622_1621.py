# Generated by Django 3.2.23 on 2024-06-22 10:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0010_filehandle_content_name'),
    ]

    operations = [
        migrations.AddField(
            model_name='filehandle',
            name='share_admin',
            field=models.CharField(default='default_admin_share', max_length=255),
        ),
        migrations.AddField(
            model_name='filehandle',
            name='share_doctor',
            field=models.CharField(default='default_doctor_share', max_length=255),
        ),
        migrations.AddField(
            model_name='filehandle',
            name='share_user',
            field=models.CharField(default='default_user_share', max_length=255),
        ),
    ]
