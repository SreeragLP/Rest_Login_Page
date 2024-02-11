from django.db import models

class UserAccount(models.Model):
    username = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=100)
    confirmed = models.BooleanField(default=False)

    def __str__(self):
        return self.email
