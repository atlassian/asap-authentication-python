from typing import Callable, Iterable, Optional

from ..common.backend import Backend
from ..common.decorators import _restrict_asap, _with_asap
from .backend import DjangoBackend


def with_asap(
    func: Optional[Callable] = None,
    issuers: Optional[Iterable[str]] = None,
    required: bool = True,
    subject_should_match_issuer: Optional[bool] = None,
) -> Callable:
    """Decorator to allow endpoint-specific ASAP authentication.

    If authentication fails, a 401 or 403 response will be returned. Otherwise,
    the decorated function will be executed.

    The ASAP claimset will be set on request.asap_claims for further
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
        func, DjangoBackend(), issuers, required, subject_should_match_issuer
    )


def restrict_asap(
    func: Optional[Callable] = None,
    backend: Optional[Backend] = None,
    issuers: Optional[Iterable[str]] = None,
    required: bool = True,
    subject_should_match_issuer: Optional[bool] = None,
) -> Callable:
    """Decorator to allow endpoint-specific ASAP authorization policies.

    This decorator assumes that request.asap_claims has previously been set by
    the asap_middleware.

    If the token does not meet the requirements imposed by the decorator, a 401
    or 403 response will be returned. Otherwise, the decorated function will be
    executed.

    :param list func: The view to decorate.
    :param list issuers: A list of valid token issuers that can access this
                         endpoint.
    :param boolean required: Whether or not to require ASAP on this endpoint.
    :param boolean subject_should_match_issuer: Indicate whether the subject
                                                must match the issuer for a
                                                token to be considered valid.
    """
    issuers = issuers if issuers is not None else []
    return _restrict_asap(
        func, DjangoBackend(), issuers, required, subject_should_match_issuer=None
    )
