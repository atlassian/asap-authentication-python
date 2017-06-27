from functools import wraps

from django.conf import settings
from django.http.response import HttpResponse
from requests.exceptions import (HTTPError, ConnectionError)
from jwt.exceptions import (InvalidIssuerError, InvalidTokenError)

import atlassian_jwt_auth
from .utils import parse_jwt, verify_issuers


def requires_asap(issuers=None):
    """Decorator for Django endpoints to require ASAP

    :param list issuers: *required The 'iss' claims that this endpoint is from.
    """
    def requires_asap_decorator(func):
        @wraps(func)
        def requires_asap_wrapper(request, *args, **kwargs):
            verifier = _get_verifier()
            auth = request.META.get('HTTP_AUTHORIZATION', b'').split(b' ')
            if not auth or len(auth) != 2:
                return HttpResponse('Unauthorized', status=401)
            error_message = None
            try:
                asap_claims = parse_jwt(verifier, auth[1])
                verify_issuers(asap_claims, issuers)
                request.asap_claims = asap_claims
                return func(request, *args, **kwargs)
            except HTTPError:
                # Couldn't find key in key server
                error_message = 'Unauthorized: Invalid key'
            except ConnectionError:
                # Also couldn't find key in key-server
                error_message = 'Unauthorized: Backend server connection error'
            except InvalidIssuerError:
                error_message = 'Unauthorized: Invalid token issuer'
            except InvalidTokenError:
                # Something went wrong with decoding the JWT
                error_message = 'Unauthorized: Invalid token'
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
