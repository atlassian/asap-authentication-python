from functools import wraps

from django.conf import settings
from django.http.response import HttpResponse
from requests.exceptions import (HTTPError, ConnectionError)
from jwt.exceptions import (InvalidIssuerError, InvalidTokenError)

import atlassian_jwt_auth
from .utils import parse_jwt, verify_issuers


def requires_asap(issuers):
    """Decorator for Django endpoints to require ASAP

    :param list issuers: *required The 'iss' claims that this endpoint is from.
    """
    def requires_asap_decorator(func):
        @wraps(func)
        def requires_asap_wrapper(request, *args, **kwargs):
            verifier = _get_verifier()
            auth = request.META.get('AUTHORIZATION', '').split(b' ')
            if not auth or len(auth) != 2:
                return HttpResponse('Unauthorized', status=401)

            try:
                asap_claims = parse_jwt(verifier, auth[1])
                verify_issuers(asap_claims, issuers)
                request.asap_claims = asap_claims
                return func(request, *args, **kwargs)
            except HTTPError:
                # Couldn't find key in key server
                return HttpResponse('Unauthorized: Invalid key', status=401)
            except ConnectionError:
                # Also couldn't find key in key-server
                return HttpResponse(
                    'Unauthorized: Backend server connection error',
                    status=401)
            except InvalidIssuerError:
                return HttpResponse('Unauthorized: Invalid token issuer',
                                    status=401)
            except InvalidTokenError:
                # Something went wrong with decoding the JWT
                return HttpResponse('Unauthorized: Invalid token',
                                    status=401)

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
