from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.contrib.auth.decorators import login_required
from functools import wraps

# TODO: Doesnt work as intended
# Instead of `/login` -> `?next=REDIRECT` it goes to `/` (admin)...
def admin_only(view_func):
    if settings.DOMAIN:
        admin_login_url = f"http://admin.{settings.DOMAIN}/login/"
    else:
        admin_login_url = '/admin/login/'

    @wraps(view_func)
    @login_required(login_url=admin_login_url)  # Redirect to login page
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_staff:  # Only Admin
            raise PermissionDenied  # Return 403 Forbidden
        return view_func(request, *args, **kwargs)
    return _wrapped_view
