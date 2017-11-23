import logging

from django.conf import settings
from django.http.response import HttpResponse
from jwt.exceptions import InvalidIssuerError


def parse_jwt(verifier, encoded_jwt):
    """Decode an encoded JWT using stored config."""
    claims = verifier.verify_jwt(
        encoded_jwt,
        settings.ASAP_VALID_AUDIENCE,
        leeway=getattr(settings, 'ASAP_VALID_LEEWAY', 0)
    )
    return claims


def verify_issuers(asap_claims, issuers=None):
    """Verify that the issuer in the claims is valid and is expected."""
    claim_iss = asap_claims.get('iss')
    logger = logging.getLogger(__name__)

    if issuers and (claim_iss not in issuers):
        # Raise early if the specific issuer isn't expected
        message = 'Issuer not in valid issuers for this endpoint'
        logger.error(message, extra={'iss': claim_iss})

        raise InvalidIssuerError(message)

    valid_issuers = settings.ASAP_VALID_ISSUERS
    if valid_issuers and claim_iss not in valid_issuers:
        message = 'Issuer not in valid issuers for this application'
        logger.error(message, extra={'iss': claim_iss})

        raise InvalidIssuerError(message)


def _build_response(message, status, headers=None):
    if headers is None:
        headers = {}

    response = HttpResponse(message, status=status)
    for header, value in headers.items():
        response[header] = value

    return response
