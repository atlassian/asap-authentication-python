from functools import wraps

import django.conf
from django.http.response import HttpResponse

from .utils import verify_issuers, _build_response
from ..server.helpers import _requires_asap
from ..server.helpers import Backend


class DjangoBackend(Backend):

    def get_request_header_value(self, request, header_name):
        return request.META.get(header_name, None)

    def get_request_auth_header_value(self, request):
        auth = self.get_request_header_value(request, 'HTTP_AUTHORIZATION')
        if auth is None:
            return b''
        return auth

    def get_setting(self, name, default=None):
        return getattr(django.conf.settings, name, default)


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
            backend = DjangoBackend()
            err_response = _requires_asap(
                verifier=backend.get_verifier(subject_should_match_issuer),
                auth=backend.get_request_auth_header_value(request),
                parse_jwt_func=backend.parse_jwt,
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
