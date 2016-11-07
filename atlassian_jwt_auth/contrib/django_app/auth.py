import logging

import atlassian_jwt_auth
import jwt
import requests

from django.conf import settings
from django.utils.module_loading import import_string

from .models import Issuer


logger = logging.getLogger(__name__)


class ASAPAuthBackend():
    def authenticate(token):
        verifier = _get_verifier()
        allowed_aud = settings.ASAP_ALLOWED_AUDIENCE

        try:
            claims = verifier.verify_jwt(
                token, allowed_aud, leeway=60
            )
        except (
            requests.exceptions.HTTPError,
            requests.exceptions.ConnectionError,
            jwt.Exceptions.InvalidTokenError
        ):
            logging.exception(
                'Authentication failed while verifying ASAP token'
            )
            return None

        try:
            return Issuer.objects.get(issuer=claims['iss']).user
        except Issuer.DoesNotExist:
            return None


def _get_verifier():
    """Returns a verifier for ASAP JWT tokens basd on application settings"""
    retriever_cls = getattr(settings, 'ASAP_KEY_RETRIEVER', 'atlassian_jwt_auth.HTTPSPublicKeyRetriever')
    retriever = import_string(retriever_cls)(settings.ASAP_PUBLICKEY_REPOSITORY)

    return atlassian_jwt_auth.JWTAuthVerifier(retriever)
