from django.urls import path
from . import views

urlpatterns = [
    path('', views.DashboardView.as_view(), name='dashboard'),
    path('filter/', views.FilterView.as_view(), name='filter'),
    path('api/filter/', views.filter_logs, name='filter_logs'),
]

from django.conf import settings
from django.shortcuts import redirect
from django.conf.urls import handler404
handler404 = lambda request, exception: redirect(settings.JAM)