from functools import wraps

from django.http.response import HttpResponse

from atlassian_jwt_auth.frameworks.django.decorators import with_asap


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


def requires_asap(issuers=None, subject_should_match_issuer=None, func=None):
    """Decorator for Django endpoints to require ASAP

    :param list issuers: *required The 'iss' claims that this endpoint is from.
    """
    return with_asap(func=func,
                     required=True,
                     issuers=issuers,
                     subject_should_match_issuer=subject_should_match_issuer)
