from functools import wraps

from django.conf import settings
from django.http.response import HttpResponse

import atlassian_jwt_auth
from .utils import parse_jwt, verify_issuers, _build_response
from ..server.helpers import _requires_asap


def validate_asap(issuers=None, subjects=None, required=True):
    """Decorator to allow endpoint-specific ASAP authorization, assuming ASAP
    authentication has already occurred.

    :param list issuers: A list of issuers that are allowed to use the
        endpoint.
    :param list subjects: A list of subjects that are allowed to use the
        endpoint.
    :param boolean required: Whether or not to require ASAP on this endpoint.
        Note that requirements will be still be verified if claims are present.
    """
    def validate_asap_decorator(func):
        @wraps(func)
        def validate_asap_wrapper(request, *args, **kwargs):
            asap_claims = getattr(request, 'asap_claims', None)
            if required and not asap_claims:
                message = 'Unauthorized: Invalid or missing token'
                response = HttpResponse(message, status=401)
                response['WWW-Authenticate'] = 'Bearer'
                return response

            if asap_claims:
                iss = asap_claims['iss']
                if issuers and iss not in issuers:
                    message = 'Forbidden: Invalid token issuer'
                    return HttpResponse(message, status=403)

                sub = asap_claims.get('sub')
                if subjects and sub not in subjects:
                    message = 'Forbidden: Invalid token subject'
                    return HttpResponse(message, status=403)

            return func(request, *args, **kwargs)

        return validate_asap_wrapper
    return validate_asap_decorator


def requires_asap(issuers=None, subject_should_match_issuer=None):
    """Decorator for Django endpoints to require ASAP

    :param list issuers: *required The 'iss' claims that this endpoint is from.
    """
    def requires_asap_decorator(func):
        @wraps(func)
        def requires_asap_wrapper(request, *args, **kwargs):
            verifier = _get_verifier(subject_should_match_issuer)
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


def _get_verifier(subject_should_match_issuer=None):
    """Return a verifier for ASAP JWT tokens based on settings"""
    retriever_cls = getattr(settings, 'ASAP_KEY_RETRIEVER_CLASS',
                            atlassian_jwt_auth.HTTPSPublicKeyRetriever)
    retriever = retriever_cls(
        base_url=getattr(settings, 'ASAP_PUBLICKEY_REPOSITORY')
    )
    if subject_should_match_issuer is None:
        subject_should_match_issuer = getattr(
            settings, 'ASAP_SUBJECT_SHOULD_MATCH_ISSUER', None)
    v_kwargs = {}
    if subject_should_match_issuer is not None:
        v_kwargs['subject_should_match_issuer'] = subject_should_match_issuer
    return atlassian_jwt_auth.JWTAuthVerifier(retriever, **v_kwargs)
