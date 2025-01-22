import hashlib
from pathlib import Path
from django.db import models
from django.core.files.storage import FileSystemStorage
from django.conf import settings
from .settings import UPLOAD_PATH

class UploaderStorage(FileSystemStorage):
    def __init__(self, *args, **kwargs):
        # Files stored in  /appname/storage/uploads
        # Files served via /appname_route/uploads/filename
        kwargs['location'] = Path(settings.BASE_DIR) / 'uploader/storage/uploads/'
        kwargs['base_url'] = UPLOAD_PATH
        super().__init__(*args, **kwargs)


def sizeof_fmt(num, suffix="B"):
    """
    Convert a file size in bytes to a human-readable format.
    https://stackoverflow.com/a/1094933
    """
    for unit in ("", "Kb", "Mb", "Gb"):
        if abs(num) < 1024.0:
            return f"{num:3.2f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Gb{suffix}"


def calculate_sha256(file_input) -> str:
    file_hash = hashlib.sha256()

    if isinstance(file_input, str):
        # If file_input is a string (filename), open the file
        with open(file_input, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                file_hash.update(byte_block)
    else:
        # If file_input is a file descriptor, use it directly
        for byte_block in iter(lambda: file_input.read(4096), b""):
            file_hash.update(byte_block)

    return file_hash.hexdigest()


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
            self.sha256sum = calculate_sha256(self.file)
            self.size = sizeof_fmt(self.file.size)

        elif self.text and not self.file:
            filepath = Path(self.__storage.location) / self.title

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(self.text)

            with open(filepath, 'rb') as f:
                self.sha256sum = calculate_sha256(f)

            self.size = sizeof_fmt(filepath.stat().st_size)
            self.file.name = filepath.name

        # # Check if an object with the same sha256sum already exists
        # if self.__class__.objects.filter(sha256sum=self.sha256sum).exists():
        #     raise ValidationError(f"An object with the same sha256sum ({self.sha256sum}) already exists.")

        super().save(*args, **kwargs)

    def __str__(self):
        return self.title
