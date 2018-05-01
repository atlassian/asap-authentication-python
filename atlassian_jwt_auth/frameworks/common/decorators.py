from functools import wraps
from jwt.exceptions import InvalidIssuerError, InvalidTokenError
from .utils import process_asap_token, _validate_claims


def _with_asap(func=None, backend=None, issuers=None, required=None,
               subject_should_match_issuer=None):
    if backend is None:
        raise ValueError(
            'Invalid value for backend. Use a subclass instead.'
        )

    def with_asap_decorator(func):
        @wraps(func)
        def with_asap_wrapper(*args, **kwargs):
            request = None
            if len(args) > 0:
                request = args[0]

            error_response = process_asap_token(
                request, backend, issuers, required,
                subject_should_match_issuer
            )

            if error_response:
                return error_response

            return func(*args, **kwargs)

        return with_asap_wrapper

    if callable(func):
        return with_asap_decorator(func)

    return with_asap_decorator


def _restrict_asap(func=None, backend=None, issuers=None,
                   required=None, subject_should_match_issuer=None):
    """Decorator to allow endpoint-specific ASAP authorization, assuming ASAP
    authentication has already occurred.
    """
    def restrict_asap_decorator(func):
        @wraps(func)
        def restrict_asap_wrapper(request, *args, **kwargs):
            asap_claims = getattr(request, 'asap_claims', None)
            error_response = None

            if required and not asap_claims:
                return backend.get_401_response(
                    'Unauthorized'
                )

            try:
                _validate_claims(
                    asap_claims, issuers, subject_should_match_issuer,
                    backend.settings
                )

            except InvalidIssuerError:
                error_response = backend.get_403_response(
                    'Forbidden: Invalid token issuer'
                )
            except InvalidTokenError:
                error_response = backend.get_401_response(
                    'Unauthorized: Invalid token'
                )

            if error_response and required:
                return error_response

            return func(request, *args, **kwargs)

        return restrict_asap_wrapper

    if callable(func):
        return restrict_asap_decorator(func)

    return restrict_asap_decorator
