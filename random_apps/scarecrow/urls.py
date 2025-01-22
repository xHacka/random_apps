from django.urls import path
from django.views.generic import TemplateView
from . import views

urlpatterns = [
    path('', views.home),

    # https://stackoverflow.com/a/58098475
    path('robots.txt', TemplateView.as_view(template_name="robots.txt", content_type='text/plain')),
]
