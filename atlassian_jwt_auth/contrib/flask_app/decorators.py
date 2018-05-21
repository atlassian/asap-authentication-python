from atlassian_jwt_auth.frameworks.flask.decorators import with_asap


def requires_asap(f, issuers=None, subject_should_match_issuer=None):
    """
    Wrapper for Flask endpoints to make them require asap authentication to
    access.
    """

    return with_asap(func=f,
                     required=True,
                     issuers=issuers,
                     subject_should_match_issuer=subject_should_match_issuer)
