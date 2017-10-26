from jwt.compat import text_type
import jwt.exceptions


def _requires_asap(verifier, auth, parse_jwt_func, build_response,
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
    try:
        scheme, auth = auth.split(b' ')
    except ValueError:
        scheme = b''

    if scheme.lower() != b'bearer':
        return build_response('Unauthorized', status=401, headers={
                              'WWW-Authenticate': 'Bearer'})
    try:
        asap_claims = parse_jwt_func(verifier, auth)
        if verify_issuers_func is not None:
            verify_issuers_func(asap_claims, issuers)
        asap_claim_holder.asap_claims = asap_claims
    except jwt.exceptions.InvalidIssuerError as e:
        message = 'Forbidden: Invalid token issuer'
        return build_response(message, status=403)
    except jwt.exceptions.InvalidTokenError as e:
        # Something went wrong with decoding the JWT
        message = 'Unauthorized: Invalid token'
        return build_response(message, status=401, headers={
                              'WWW-Authenticate': 'Bearer'})
    return None
