import logging

import jwt.exceptions
import requests.exceptions

from atlassian_jwt_auth.exceptions import (
    PublicKeyRetrieverException,
)


def _requires_asap(verifier, auth, parse_jwt_func, response_class,
                   asap_claim_holder,
                   verify_issuers_func=None,
                   issuers=None,
                   ):
    """ Internal code used in various requires_asap decorators. """
    message, exception = None, None
    if not auth or len(auth) != 2:
        return response_class('Unauthorized', status=401)
    try:
        asap_claims = parse_jwt_func(verifier, auth[1])
        if verify_issuers_func is not None:
            verify_issuers_func(asap_claims, issuers)
        asap_claim_holder.asap_claims = asap_claims
    except requests.exceptions.HTTPError as e:
        # Couldn't find key in key server
        message = 'Unauthorized: Invalid key'
        exception = e
    except (requests.exceptions.ConnectionError,
            PublicKeyRetrieverException) as e:
        message = 'Unauthorized: Backend server connection error'
        exception = e
    except jwt.exceptions.InvalidIssuerError as e:
        message = 'Unauthorized: Invalid token issuer'
        exception = e
    except jwt.exceptions.InvalidTokenError as e:
        # Something went wrong with decoding the JWT
        message = 'Unauthorized: Invalid token'
        exception = e
    if message is not None:
        logger = logging.getLogger(__name__)
        logger.error(message,
                     extra={'original_message': str(exception)})
        return response_class(message, status=401)
    return None
