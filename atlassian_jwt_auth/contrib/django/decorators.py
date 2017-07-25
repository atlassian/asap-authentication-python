import logging
from functools import wraps

from django.conf import settings
from django.http.response import HttpResponse
from django.utils import six
from jwt.exceptions import InvalidIssuerError, InvalidTokenError

import atlassian_jwt_auth
from atlassian_jwt_auth.exceptions import PublicKeyRetrieverException
from .utils import parse_jwt, verify_issuers

logger = logging.getLogger(__name__)


def requires_asap(issuers=None):
    """Decorator for Django endpoints to require ASAP

    :param list issuers: *required The 'iss' claims that this endpoint is from.
    """
    def requires_asap_decorator(func):
        @wraps(func)
        def requires_asap_wrapper(request, *args, **kwargs):
            verifier = _get_verifier()
            auth_header = request.META.get('HTTP_AUTHORIZATION', b'')
            # Per PEP-3333, headers must be in ISO-8859-1 or use an RFC-2047
            # MIME encoding. We don't really care about MIME encoded
            # headers, but some libraries allow sending bytes (Django tests)
            # and some (requests) always send str so we need to convert if
            # that is the case to properly support Python 3.
            if isinstance(auth_header, six.string_types):
                auth_header = auth_header.encode(encoding='iso-8859-1')
            auth = auth_header.split(b' ')
            if not auth or len(auth) != 2:
                return HttpResponse('Unauthorized', status=401)
            error_message = None
            try:
                asap_claims = parse_jwt(verifier, auth[1])
                verify_issuers(asap_claims, issuers)
                request.asap_claims = asap_claims
                return func(request, *args, **kwargs)
            except PublicKeyRetrieverException as e:
                # Couldn't find key in key server, log the error, but do
                # not show to clients.
                error_message = 'Unauthorized: Could not load public key'
                logger.exception(error_message)
            except InvalidIssuerError as e:
                error_message = 'Unauthorized: %s' % e
                logger.exception(error_message)
            except InvalidTokenError as e:
                # Something went wrong with decoding the JWT
                error_message = 'Unauthorized: %s' % e
                logger.exception(error_message)

            if error_message is not None:
                return HttpResponse(error_message, status=401)

        return requires_asap_wrapper
    return requires_asap_decorator


def _get_verifier():
    """Return a verifier for ASAP JWT tokens based on settings"""
    retriever_cls = getattr(settings, 'ASAP_KEY_RETRIEVER_CLASS',
                            atlassian_jwt_auth.HTTPSPublicKeyRetriever)
    retriever = retriever_cls(
        base_url=getattr(settings, 'ASAP_PUBLICKEY_REPOSITORY')
    )
    return atlassian_jwt_auth.JWTAuthVerifier(retriever)
