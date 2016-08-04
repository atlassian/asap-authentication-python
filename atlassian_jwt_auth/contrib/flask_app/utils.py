from flask import current_app
import jwt.exceptions
import requests.exceptions


def parse_jwt(verifier, encoded_jwt):
    """Decode an encoded JWT using stored config."""
    try:
        claims = verifier.verify_jwt(
            encoded_jwt,
            current_app.config.asap['VALID_AUDIENCE'],
            leeway=60,
            verify=current_app.config.asap.get('VERIFY_TLS_CERT', True)
        )

        valid_issuers = current_app.config.asap.get('VALID_ISSUERS')
        if valid_issuers and claims.get('iss') not in valid_issuers:
            return False

        return claims

    except requests.exceptions.HTTPError:
        # Couldn't find key in key server
        return False
    except requests.exceptions.ConnectionError:
        # Also couldn't find key in key-server
        return False
    except jwt.exceptions.InvalidTokenError:
        # Something went wrong with decoding the JWT
        return False
