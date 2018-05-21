from functools import wraps
from jwt.exceptions import InvalidIssuerError, InvalidTokenError

from .asap import _process_asap_token, _verify_issuers
from .utils import SettingsDict


def _with_asap(func=None, backend=None, issuers=None, required=True,
               subject_should_match_issuer=None):
    if backend is None:
        raise ValueError(
            'Invalid value for backend. Use a subclass instead.'
        )

    def with_asap_decorator(func):
        @wraps(func)
        def with_asap_wrapper(*args, **kwargs):
            settings = _update_settings_from_kwargs(
                backend.settings,
                issuers=issuers, required=required,
                subject_should_match_issuer=subject_should_match_issuer
            )

            request = None
            if len(args) > 0:
                request = args[0]

            error_response = _process_asap_token(
                request, backend, settings
            )

            if error_response is not None:
                return error_response

            return func(*args, **kwargs)

        return with_asap_wrapper

    if callable(func):
        return with_asap_decorator(func)

    return with_asap_decorator


def _restrict_asap(func=None, backend=None, issuers=None,
                   required=True, subject_should_match_issuer=None):
    """Decorator to allow endpoint-specific ASAP authorization, assuming ASAP
    authentication has already occurred.
    """

    def restrict_asap_decorator(func):
        @wraps(func)
        def restrict_asap_wrapper(request, *args, **kwargs):
            settings = _update_settings_from_kwargs(
                backend.settings,
                issuers=issuers, required=required,
                subject_should_match_issuer=subject_should_match_issuer
            )
            asap_claims = getattr(request, 'asap_claims', None)
            error_response = None

            if required and not asap_claims:
                return backend.get_401_response(
                    'Unauthorized', request=request
                )

            try:
                _verify_issuers(asap_claims, settings.ASAP_VALID_ISSUERS)
            except InvalidIssuerError:
                error_response = backend.get_403_response(
                    'Forbidden: Invalid token issuer', request=request
                )
            except InvalidTokenError:
                error_response = backend.get_401_response(
                    'Unauthorized: Invalid token', request=request
                )

            if error_response and required:
                return error_response

            return func(request, *args, **kwargs)

        return restrict_asap_wrapper

    if callable(func):
        return restrict_asap_decorator(func)

    return restrict_asap_decorator


def _update_settings_from_kwargs(settings, issuers=None, required=True,
                                 subject_should_match_issuer=None):
    settings = settings.copy()

    if issuers is not None:
        settings['ASAP_VALID_ISSUERS'] = set(issuers)

    if required is not None:
        settings['ASAP_REQUIRED'] = required

    if subject_should_match_issuer is not None:
        settings['ASAP_SUBJECT_SHOULD_MATCH_ISSUER'] = (
            subject_should_match_issuer
        )

    return SettingsDict(settings)
