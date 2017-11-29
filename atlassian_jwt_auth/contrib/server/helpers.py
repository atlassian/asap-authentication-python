import logging

from jwt.compat import text_type
import jwt.exceptions

from atlassian_jwt_auth.exceptions import (
    PublicKeyRetrieverException,
)


def _requires_asap(verifier, auth, parse_jwt_func, build_response_func,
                   asap_claim_holder,
                   verify_issuers_func=None,
                   issuers=None,
                   ):
    """ Internal code used in various requires_asap decorators. """
    if isinstance(auth, text_type):
        # Per PEP-3333, headers must be in ISO-8859-1 or use an RFC-2047
        # MIME encoding. We don't really care about MIME encoded
        # headers, but some libraries allow sending bytes (Django tests)
        # and some (requests) always send str so we need to convert if
        # that is the case to properly support Python 3.
        auth = auth.encode(encoding='iso-8859-1')
    auth = auth.split(b' ')
    message, exception = None, None
    if not auth or len(auth) != 2 or auth[0].lower() != b'bearer':
        return build_response_func('Unauthorized', status=401, headers={
            'WWW-Authenticate': 'Bearer'})
    try:
        asap_claims = parse_jwt_func(verifier, auth[1])
        if verify_issuers_func is not None:
            verify_issuers_func(asap_claims, issuers)
        asap_claim_holder.asap_claims = asap_claims
    except PublicKeyRetrieverException as e:
        if e.status_code not in (403, 404):
            # Any error other than "not found" is a problem and should be dealt
            # with elsewhere.
            # Note that we treat 403 like 404 to account for the fact that
            # a server configured to secure directory listings will return 403
            # for a missing file to avoid leaking information.
            raise
        # Couldn't find key in key server
        message = 'Unauthorized: Invalid key'
        exception = e
    except jwt.exceptions.InvalidIssuerError as e:
        message = 'Forbidden: Invalid token issuer'
        exception = e
    except jwt.exceptions.InvalidTokenError as e:
        # Something went wrong with decoding the JWT
        message = 'Unauthorized: Invalid token'
        exception = e
    if message is not None:
        logger = logging.getLogger(__name__)
        logger.debug(message,
                     extra={'original_message': str(exception)})
        if message.startswith('Unauthorized:'):
            kwargs = {
                'status': 401,
                'headers': {'WWW-Authenticate': 'Bearer'},
            }
        elif message.startswith('Forbidden:'):
            kwargs = {'status': 403}
        return build_response_func(message, **kwargs)
    return None
