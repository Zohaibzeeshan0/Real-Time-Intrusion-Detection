from django.db import models
from django.contrib.auth.models import User

class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    subject = models.CharField(max_length=200)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.subject}"



class CapturedTraffic(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    src_ip = models.GenericIPAddressField()
    dest_ip = models.GenericIPAddressField()
    protocol = models.CharField(max_length=10)
    prediction = models.CharField(max_length=50)

    def __str__(self):
        return f"{self.timestamp} - {self.src_ip} -> {self.dest_ip} ({self.prediction})"
