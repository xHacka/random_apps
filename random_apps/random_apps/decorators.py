from django.core.exceptions import PermissionDenied
from django.contrib.auth.decorators import login_required
from functools import wraps


def admin_only(view_func):
    @wraps(view_func)
    @login_required(login_url='/admin/login/')  # Redirect to login page
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_staff:  # Only Admin
            raise PermissionDenied  # Return 403 Forbidden
        return view_func(request, *args, **kwargs)
    return _wrapped_view
