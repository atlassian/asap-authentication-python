from functools import wraps
import warnings

from django.conf import settings
from django.http.response import HttpResponse

import atlassian_jwt_auth
from .utils import parse_jwt, verify_issuers
from ..server.helpers import _requires_asap


def validate_asap(issuers=None, subjects=None, required=True):
    """Decorator to allow endpoint-specific ASAP validation.

    :param list issuers: A list of issuers that are allowed to use the
        endpoint.
    :param subject: A list of subjects or a function to determine allowed
        subjects for the endpoint.
    :param boolean required: Whether or not to require ASAP on this endpoint.
        Note that requirements will be still be verified if claims are present.
    """
    def validate_asap_decorator(func):
        @wraps(func)
        def validate_asap_wrapper(request, *args, **kwargs):
            asap_claims = getattr(request, 'asap_claims', {})
            if required and not asap_claims:
                message = 'Unauthorized: Invalid or missing token'
                return HttpResponse(message, status=401)

            iss = asap_claims.get('iss')
            if issuers and iss not in issuers:
                message = 'Unauthorized: Invalid token issuer'
                return HttpResponse(message, status=401)

            sub = asap_claims.get('sub')
            if callable(subjects):
                sub_allowed = subjects(sub)
            elif isinstance(subjects, list):
                sub_allowed = sub in subjects
            else:
                sub_allowed = True

            if not sub_allowed:
                message = 'Forbidden: Invalid token subject'
                return HttpResponse(message, status=403)

            return func(request, *args, **kwargs)

        return validate_asap_wrapper
    return validate_asap_decorator


def requires_asap(issuers=None):
    """Decorator for Django endpoints to require ASAP

    :param list issuers: *required The 'iss' claims that this endpoint is from.

    DEPRECATED: use ASAPMiddleware and validate_asap instead.
    """
    def requires_asap_decorator(func):
        warnings.warn("requires_asap is deprecated; use ASAPMiddleware and "
                      "validate_asap instead.", DeprecationWarning)

        @wraps(func)
        def requires_asap_wrapper(request, *args, **kwargs):
            verifier = _get_verifier()
            auth_header = request.META.get('HTTP_AUTHORIZATION', b'')
            err_response = _requires_asap(
                verifier=verifier,
                auth=auth_header,
                parse_jwt_func=parse_jwt,
                build_response_func=_build_response,
                asap_claim_holder=request,
                verify_issuers_func=verify_issuers,
                issuers=issuers,
            )
            if err_response is None:
                return func(request, *args, **kwargs)
            return err_response

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


def _build_response(message, status, headers=None):
        if headers is None:
            headers = {}

        response = HttpResponse(message, status=status)
        for header, value in headers.items():
            response[header] = value

        return response
