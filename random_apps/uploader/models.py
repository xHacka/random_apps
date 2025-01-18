from hashlib import file_digest
from pathlib import Path
from django.db import models
from django.core.files.storage import FileSystemStorage
from django.conf import settings


class UploaderStorage(FileSystemStorage):
    def __init__(self, *args, **kwargs):
        # Files stored in  /appname/storage/uploads
        # Files served via /appname_route/uploads/filename
        kwargs['location'] = Path(settings.BASE_DIR) / 'uploader/storage/uploads/'
        kwargs['base_url'] = '/up/uploads/'
        super().__init__(*args, **kwargs)


def sizeof_fmt(num, suffix="B"):
    """
    Convert a file size in bytes to a human-readable format.
    https://stackoverflow.com/a/1094933
    """
    print(vars())
    for unit in ("", "Kb", "Mb", "Gb"):
        if abs(num) < 1024.0:
            return f"{num:3.2f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Gb{suffix}"


class Upload(models.Model):
    __storage = UploaderStorage()

    title = models.CharField(max_length=255)
    file = models.FileField(upload_to='', blank=True, storage=__storage)
    text = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    sha256sum = models.CharField(max_length=64, blank=True)
    size = models.CharField(max_length=20, blank=True)

    class Meta:
        ordering = ['-created_at']

    def save(self, *args, **kwargs):
        if self.file:
            self.sha256sum = file_digest(self.file, 'sha256').hexdigest()
            self.size = sizeof_fmt(self.file.size)

        elif self.text and not self.file:
            filepath = Path(self.__storage.location) / self.title

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(self.text)

            with open(filepath, 'rb') as f:
                self.sha256sum = file_digest(f, 'sha256').hexdigest()

            print(f'{filepath.stat()=}')
            print(f'{filepath.stat().st_size=}')
            self.size = sizeof_fmt(filepath.stat().st_size)
            self.file.name = filepath.name

        # # Check if an object with the same sha256sum already exists
        # if self.__class__.objects.filter(sha256sum=self.sha256sum).exists():
        #     raise ValidationError(f"An object with the same sha256sum ({self.sha256sum}) already exists.")

        super().save(*args, **kwargs)

    def __str__(self):
        return self.title
