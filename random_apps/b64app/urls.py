from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),

    path('e/', views.encode, name='encode'),
    path('d/', views.decode, name='decode'),

    path('es/', views.show_encoded, name='show_encoded'),
    path('ds/', views.show_decoded, name='show_decoded'),
]

