# Generated by Django 4.1.4 on 2022-12-10 12:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('map', '0005_alter_route_coords_alter_route_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='route',
            name='description',
            field=models.TextField(max_length=300, null=True),
        ),
        migrations.AddField(
            model_name='route',
            name='name',
            field=models.CharField(default='Article', max_length=50),
        ),
        migrations.DeleteModel(
            name='UserProfile',
        ),
    ]
