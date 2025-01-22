from django.conf import settings

UPLOAD_PATH = 'uploads/' if settings.DOMAIN else 'up/uploads/'
UPLOAD_ROOT = settings.BASE_DIR / 'uploader/storage/uploads/'
