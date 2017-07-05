from flask import current_app
from jwt.exceptions import InvalidIssuerError


def parse_jwt(verifier, encoded_jwt):
    """Decode an encoded JWT using stored config."""
    claims = verifier.verify_jwt(
        encoded_jwt,
        current_app.config['ASAP_VALID_AUDIENCE'],
        leeway=current_app.config.get('ASAP_VALID_LEEWAY', 0)
    )

    valid_issuers = current_app.config.get('ASAP_VALID_ISSUERS')
    if valid_issuers and claims.get('iss') not in valid_issuers:
        raise InvalidIssuerError

    return claims
