from django.db import models

class LogEntry(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField()
    request_method = models.CharField(max_length=10)
    path = models.TextField()
    protocol = models.CharField(max_length=10)
    status_code = models.IntegerField()
    response_size = models.IntegerField()
    referer = models.TextField(null=True, blank=True)
    user_agent = models.TextField()
    query_params = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['status_code']),
            models.Index(fields=['request_method']),
            models.Index(fields=['path']),
        ]