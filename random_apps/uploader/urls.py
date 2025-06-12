from django.urls import path
from django.conf.urls.static import static
from django.views.generic import TemplateView
from . import views
from .settings import UPLOAD_PATH, UPLOAD_ROOT


urlpatterns = [
    path('', views.upload, name='upload'),
    path('list/', views.upload_list, name='upload_list'),
    
    # https://stackoverflow.com/a/58098475
    path('robots.txt', TemplateView.as_view(template_name="robots.txt", content_type='text/plain')),

    # Only works in DEBUG=1
    *static(UPLOAD_PATH, document_root=UPLOAD_ROOT)
]

from django.conf import settings
from django.shortcuts import redirect
from django.conf.urls import handler404
handler404 = lambda request, exception: redirect(settings.JAM)