from django.contrib.auth.models import User
from django.db import models



class Route(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, default=None, null=True, blank=True)
    coords = models.IntegerField(default=0, null=True, blank=True)
    name = models.CharField(max_length=50, default="Article")
    description = models.TextField(max_length=300, null=True)

