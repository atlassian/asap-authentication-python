from functools import wraps

from flask import Response, current_app, g, request

import atlassian_jwt_auth
from .utils import parse_jwt
from ..server import _requires_asap


def requires_asap(f):
    """
    Wrapper for Flask endpoints to make them require asap authentication to
    access.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        verifier = _get_verifier()
        auth = request.headers.get('AUTHORIZATION', '').split(' ')
        err_response = _requires_asap(
            verifier=verifier,
            auth=auth,
            parse_jwt_func=parse_jwt,
            response_class=Response,
            asap_claim_holder=g,
        )
        if err_response is None:
            return f(*args, **kwargs)
        return err_response

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
