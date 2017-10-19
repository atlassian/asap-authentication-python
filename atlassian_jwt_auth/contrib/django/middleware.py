import logging

from jwt import InvalidAudienceError

from django.conf import settings
from django.http.response import HttpResponse
from django.utils import six
from jwt.exceptions import InvalidTokenError

import atlassian_jwt_auth
from .utils import parse_jwt, verify_issuers


class ASAPForwardedMiddleware(object):
    """Enable client auth for ASAP-enabled services that are forwarding
    non-ASAP client requests.

    This must come before any authentication middleware.
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
        self.process_request(request)
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

        self.logger = logging.getLogger(__name__)

        self.required = getattr(settings, 'ASAP_REQUIRED', True)
        self.client_auth = getattr(settings, 'ASAP_CLIENT_AUTH', False)

        # Configure verifier based on settings
        retriever_kwargs = {}
        retriever_cls = getattr(settings, 'ASAP_KEY_RETRIEVER_CLASS',
                                atlassian_jwt_auth.HTTPSPublicKeyRetriever)
        public_key_url = getattr(settings, 'ASAP_PUBLICKEY_REPOSITORY', None)
        if public_key_url:
            retriever_kwargs['base_url'] = public_key_url
        retriever = retriever_cls(**retriever_kwargs)
        self.verifier = atlassian_jwt_auth.JWTAuthVerifier(retriever)

    def process_request(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION', b'')
        # Per PEP-3333, headers must be in ISO-8859-1 or use an RFC-2047
        # MIME encoding. We don't really care about MIME encoded
        # headers, but some libraries allow sending bytes (Django tests)
        # and some (requests) always send str so we need to convert if
        # that is the case to properly support Python 3.
        if isinstance(auth_header, six.string_types):
            auth_header = auth_header.encode(encoding='iso-8859-1')
        try:
            scheme, auth = auth_header.split(b' ')
        except ValueError:
            scheme = b''

        if scheme.lower() != b'bearer':
            if not self.required:
                return
            message = 'Unauthorized: Invalid or missing token'
            return HttpResponse(message, status=401)

        try:
            asap_claims = parse_jwt(self.verifier, auth)
            verify_issuers(asap_claims)
        except InvalidAudienceError as e:
            if not self.required:
                return
            message = 'Forbidden: %s' % e
            return HttpResponse(message, status=403)
        except InvalidTokenError as e:
            if not self.required:
                return
            message = 'Unauthorized: %s' % e
            return HttpResponse(message, status=401)
        except Exception as e:
            # Something is rotten in the state of ASAP
            self.logger.error(message,
                              extra={'original_message': str(e)})
            if not self.required:
                return
            raise

        request.asap_claims = asap_claims

        if self.client_auth:
            super(ASAPMiddleware, self).process_request(request)
