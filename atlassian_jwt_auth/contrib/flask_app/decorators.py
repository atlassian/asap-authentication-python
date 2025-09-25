from typing import Callable, Iterable, Optional

from atlassian_jwt_auth.frameworks.flask.decorators import with_asap


def requires_asap(
    f: Callable,
    issuers: Optional[Iterable[str]] = None,
    subject_should_match_issuer: Optional[bool] = None,
):
    """
    Wrapper for Flask endpoints to make them require asap authentication to
    access.
    """

    return with_asap(
        func=f,
        required=True,
        issuers=issuers,
        subject_should_match_issuer=subject_should_match_issuer,
    )
