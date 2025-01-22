from django.contrib import admin
from . import models

admin.site.register(models.EncodedEntry)
admin.site.register(models.DecodedEntry)