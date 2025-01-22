from django.contrib import admin
from django.urls import path
from django.views.generic import TemplateView

urlpatterns = [
    path('', admin.site.urls),
    
    # https://stackoverflow.com/a/58098475
    path('robots.txt', TemplateView.as_view(template_name="robots.txt", content_type='text/plain')),
] 
