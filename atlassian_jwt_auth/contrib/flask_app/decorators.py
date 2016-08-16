from functools import wraps

from flask import Response, current_app, g, request
import jwt.exceptions
import requests.exceptions

import atlassian_jwt_auth
from .utils import parse_jwt


def requires_asap(f):
    """
    Wrapper for Flask endpoints to make them require asap authentication to
    access.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        verifier = _get_verifier()
        auth = request.headers.get('Authorization', '').split(' ')
        if not auth or len(auth) != 2:
            return Response('Unauthorized', 401)

        try:
            g.asap_claims = parse_jwt(verifier, auth[1])
            return f(*args, **kwargs)
        except requests.exceptions.HTTPError:
            # Couldn't find key in key server
            return Response('Unauthorized: Invalid key', 401)
        except requests.exceptions.ConnectionError:
            # Also couldn't find key in key-server
            return Response(
                'Unauthorized: Backend server connection error', 401
            )
        except jwt.exceptions.InvalidIssuer:
            return Response('Unauthorized: Invalid token issuer', 401)
        except jwt.exceptions.InvalidTokenError:
            # Something went wrong with decoding the JWT
            return Response('Unauthorized: Invalid token', 401)

    return decorated


def _get_verifier():
    """Returns a verifier for ASAP JWT tokens basd on application settings"""
    retriever_cls = current_app.config.get(
        'ASAP_KEY_RETRIEVER_CLASS', atlassian_jwt_auth.HTTPSPublicKeyRetriever
    )
    retriever = retriever_cls(
        base_url=current_app.config.get('ASAP_PUBLICKEY_REPOSITORY')
    )
    return atlassian_jwt_auth.JWTAuthVerifier(retriever)
