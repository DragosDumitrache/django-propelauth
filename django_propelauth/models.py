from django.contrib.auth.models import AbstractUser
from django.db import models


# Create your models here.
class User(AbstractUser):
    id = models.AutoField(primary_key=True)
    email = models.EmailField(blank=True, null=True)
    propelauth_id = models.TextField(max_length=100, blank=True, null=True)
    free_trial_count = models.IntegerField(default=0)
    subscribed = models.BooleanField(default=False)
