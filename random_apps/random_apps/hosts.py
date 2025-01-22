from django_hosts import patterns, host
# from django.conf import settings

host_patterns = patterns('',
    # host('www', settings.ROOT_URLCONF, name='www'),
    host('www', 'scarecrow.urls', name='www'),
    host('admin', 'scarecrow.urls_admin', name='admin'),
    host('b64', 'b64app.urls', name='b64'),
    host('up', 'uploader.urls', name='up'),
) 