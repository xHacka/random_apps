from django.urls import path
from . import views

app_name = 'ceh12quiz'

urlpatterns = [
    path('', views.quiz_view, name='quiz'),
]

from django.conf import settings
from django.shortcuts import redirect
from django.conf.urls import handler404
handler404 = lambda request, exception: redirect(settings.JAM)