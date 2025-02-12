from django.urls import path
from . import views

urlpatterns = [
    path('', views.DashboardView.as_view(), name='dashboard'),
    path('filter/', views.FilterView.as_view(), name='filter'),
    path('api/filter/', views.filter_logs, name='filter_logs'),
]