from django.conf import settings

import atlassian_jwt_auth
from ..server.helpers import _requires_asap
from .utils import parse_jwt, verify_issuers, _build_response
from .decorators import _get_verifier


class ASAPForwardedMiddleware(object):
    """Enable client auth for ASAP-enabled services that are forwarding
    non-ASAP client requests.

    This must come before any authentication middleware.

    DEPRECATED: use ASAPMiddleware instead.
    """

    def __init__(self, get_response=None):
        self.get_response = get_response

        # Rely on this header to tell us if a request has been forwarded
        # from an ASAP-enabled service; will overwrite X-Forwarded-For
        self.xfwd = getattr(settings, 'ASAP_PROXIED_FORWARDED_FOR_HEADER',
                            'HTTP_X_ASAP_FORWARDED_FOR')

        # This header won't always be set, i.e. some users will be anonymous
        self.xauth = getattr(settings, 'ASAP_PROXIED_AUTHORIZATION_HEADER',
                             'HTTP_X_ASAP_AUTHORIZATION')

    def __call__(self, request):
        early_response = self.process_request(request)
        if early_response:
            return early_response
        return self.get_response(request)

    def process_request(self, request):
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


class ASAPMiddleware(ASAPForwardedMiddleware):
    """Enable ASAP for Django applications.

    To use proxied credentials, this must come before any authentication
    middleware.
    """

    def __init__(self, get_response=None):
        super(ASAPMiddleware, self).__init__(get_response=get_response)
        self.required = getattr(settings, 'ASAP_REQUIRED', True)
        self.client_auth = getattr(settings, 'ASAP_CLIENT_AUTH', False)

        # Configure verifier based on settings
        self.verifier = _get_verifier()

    def process_request(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION', b'')
        asap_err = _requires_asap(
            verifier=self.verifier,
            auth=auth_header,
            parse_jwt_func=parse_jwt,
            build_response_func=_build_response,
            asap_claim_holder=request,
            verify_issuers_func=verify_issuers,
        )

        if asap_err and self.required:
            return asap_err
        elif self.client_auth:
            super(ASAPMiddleware, self).process_request(request)
