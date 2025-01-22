from django.urls import path
from django.conf.urls.static import static
from . import views
from .settings import UPLOAD_PATH, UPLOAD_ROOT


urlpatterns = [
    path('', views.upload, name='upload'),
    path('list/', views.upload_list, name='upload_list'),
    *static(UPLOAD_PATH, document_root=UPLOAD_ROOT)
]

print(urlpatterns)