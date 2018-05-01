from ..common.decorators import _with_asap
from .backend import FlaskBackend


def with_asap(func=None, issuers=None, required=None,
              subject_should_match_issuer=None):
    """Decorator to allow endpoint-specific ASAP authentication.

    If authentication fails, a 401 or 403 response will be returned. Otherwise,
    the decorated function will be executed.

    The ASAP claimset will be set on g.asap_claims for further
    inspection later in the request lifecycle.

    :param list func: The view to decorate.
    :param list issuers: A list of valid token issuers that can access this
                         endpoint.
    :param boolean required: Whether or not to require ASAP on this endpoint.
    :param boolean subject_should_match_issuer: Indicate whether the subject
                                                must match the issuer for a
                                                token to be considered valid.
    """
    return _with_asap(
        func, FlaskBackend(), issuers, required,
        subject_should_match_issuer
    )
