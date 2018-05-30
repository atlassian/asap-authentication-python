import warnings

from atlassian_jwt_auth.frameworks.flask.decorators import with_asap


def requires_asap(f, issuers=None, subject_should_match_issuer=None):
    """
    Wrapper for Flask endpoints to make them require asap authentication to
    access.
    """

    warnings.warn(
        "requires_asap in the contrib package is deprecated;"
        "use atlassian_jwt_auth.frameworks.django.requires_asap instead",
        DeprecationWarning
    )
    return with_asap(func=f,
                     required=True,
                     issuers=issuers,
                     subject_should_match_issuer=subject_should_match_issuer)
