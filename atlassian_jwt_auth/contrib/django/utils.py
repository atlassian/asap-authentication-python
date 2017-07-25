from django.conf import settings
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

    if issuers and (claim_iss not in issuers):
        # Raise early if the specific issuer isn't expected
        raise InvalidIssuerError(
            'Issuer `%s` not in valid issuers for this endpoint' % claim_iss)
    valid_issuers = settings.ASAP_VALID_ISSUERS
    if valid_issuers and claim_iss not in valid_issuers:
        raise InvalidIssuerError(
            'Issuer `%s` not in valid issuers for this application'
            % claim_iss)
