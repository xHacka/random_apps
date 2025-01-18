from django.db import models

class EncodedEntry(models.Model):
    original = models.TextField()  
    converted = models.TextField()  
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.created_at}] Decoded Entry: {self.original[:100]}... | {self.converted[:100]}..."

class DecodedEntry(models.Model):
    original = models.TextField()  
    converted = models.TextField()  
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.created_at}] Decoded Entry: {self.original[:100]}... | {self.converted[:100]}..."
