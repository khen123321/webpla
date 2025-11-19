from django.utils.timezone import now
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden

class UpdateLastActiveMiddleware(MiddlewareMixin):
    def process_view(self, request, view_func, view_args, view_kwargs):
        if request.user.is_authenticated:
            profile = getattr(request.user, 'profile', None)
            if profile:
                profile.last_active = now()
                profile.save(update_fields=['last_active'])
        return None

    def process_request(self, request):
        # ✅ ADD THIS - Block mobile users who somehow get authenticated
        if request.user.is_authenticated:
            # Check if user is trying to access web pages (not API)
            web_paths = ['/dashboard/', '/rewards/', '/claim-requests/', '/profile/', '/users/']
            is_web_path = any(request.path.startswith(path) for path in web_paths)
            
            if is_web_path:
                # Check if user is a mobile user
                if hasattr(request.user, 'profile') and request.user.profile.signup_source == 'mobile':
                    return HttpResponseForbidden(
                        "Access denied. Mobile app users cannot access the web interface. "
                        "Please use the mobile app."
                    )
        return None