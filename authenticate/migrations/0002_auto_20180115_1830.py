# Generated by Django 2.0.1 on 2018-01-15 18:30

import django.contrib.postgres.fields.jsonb
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('authenticate', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='resident',
            name='isVerfied',
            field=models.CharField(default='00', max_length=2),
        ),
        migrations.AlterField(
            model_name='resident',
            name='address',
            field=django.contrib.postgres.fields.jsonb.JSONField(default={'country': '', 'dist': '', 'house': '', 'lm': '', 'pc': '', 'po': '', 'state': '', 'street': '', 'subdist': '', 'vtc': ''}),
        ),
        migrations.AlterField(
            model_name='resident',
            name='phone',
            field=models.CharField(max_length=15),
        ),
    ]