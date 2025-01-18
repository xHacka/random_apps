from django.urls import path
from . import views

urlpatterns = [
    path('', views.upload, name='upload'),
    path('list/', views.upload_list, name='upload_list'),
]