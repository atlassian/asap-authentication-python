from django.conf import settings
from django.utils.deprecation import MiddlewareMixin

from atlassian_jwt_auth.frameworks.django.middleware import (
    OldStyleASAPMiddleware
)


class ProxiedAsapMiddleware(OldStyleASAPMiddleware, MiddlewareMixin):
    """Enable client auth for ASAP-enabled services that are forwarding
    non-ASAP client requests.

    This must come before any authentication middleware."""

    def __init__(self, get_response=None):
        super(ProxiedAsapMiddleware, self).__init__()
        self.get_response = get_response

        # Rely on this header to tell us if a request has been forwarded
        # from an ASAP-enabled service; will overwrite X-Forwarded-For
        self.xfwd = getattr(settings, 'ASAP_PROXIED_FORWARDED_FOR_HEADER',
                            'HTTP_X_ASAP_FORWARDED_FOR')

        # This header won't always be set, i.e. some users will be anonymous
        self.xauth = getattr(settings, 'ASAP_PROXIED_AUTHORIZATION_HEADER',
                             'HTTP_X_ASAP_AUTHORIZATION')

    def process_request(self, request):
        error_response = super(ProxiedAsapMiddleware, self).process_request(
            request
        )

        if error_response:
            return error_response

        forwarded_for = request.META.pop(self.xfwd, None)
        if forwarded_for is None:
            return

        request.asap_forwarded = True
        request.META['HTTP_X_FORWARDED_FOR'] = forwarded_for

        asap_auth = request.META.pop('HTTP_AUTHORIZATION', None)
        orig_auth = request.META.pop(self.xauth, None)

        # Swap original client header in to allow regular auth middleware
        if orig_auth is not None:
            request.META['HTTP_AUTHORIZATION'] = orig_auth
        if asap_auth is not None:
            request.META[self.xauth] = asap_auth

    def process_view(self, request, view_func, view_args, view_kwargs):
        if not hasattr(request, 'asap_forwarded'):
            return

        # swap headers back into place
        asap_auth = request.META.pop(self.xauth, None)
        orig_auth = request.META.pop('HTTP_AUTHORIZATION', None)

        if asap_auth is not None:
            request.META['HTTP_AUTHORIZATION'] = asap_auth
        if orig_auth is not None:
            request.META[self.xauth] = orig_auth
