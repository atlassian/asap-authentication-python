from functools import wraps

from flask import Response, current_app, request

import atlassian_jwt_auth
from atlassian_jwt_auth.contrib.flask_app.utils import parse_jwt


def requires_asap(f):
    """
    Wrapper for Flask endpoints to make them require authentication to access.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        verifier = _get_verifier()
        auth = request.headers.get('Authorization')
        if not auth or not parse_jwt(verifier, auth.split(" ")[1]):
            return Response('Unauthorized', 401)
        return f(*args, **kwargs)
    return decorated


def _get_verifier():
    """Returns a verifier based on config.asap['PUBLICKEY_REPOSITORY']"""
    return atlassian_jwt_auth.JWTAuthVerifier(
        atlassian_jwt_auth.HTTPSPublicKeyRetriever(
            current_app.config.asap['PUBLICKEY_REPOSITORY']
        )
    )
