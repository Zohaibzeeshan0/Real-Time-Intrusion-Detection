from django.contrib import admin
from . import models
from django.contrib.auth.models import User
# Register your models here.
admin.site.register(models.CapturedTraffic)
#admin.site.register(User)
admin.site.register(models.Contact)