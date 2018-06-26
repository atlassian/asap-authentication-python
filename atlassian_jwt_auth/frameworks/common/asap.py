from jwt.exceptions import InvalidIssuerError, InvalidTokenError

from atlassian_jwt_auth.exceptions import (
    PublicKeyRetrieverException,
    NoTokenProvidedError,
)


def _process_asap_token(request, backend, settings):
    """ Verifies an ASAP token, validates the claims, and returns an error
    response"""
    token = backend.get_asap_token(request)
    error_response = None
    if token is None and not settings.ASAP_REQUIRED and (
            settings.ASAP_REQUIRED is not None):
        return

    if request and settings.ASAP_EXCLUDE_PATHS:
        path = request.environ.get('PATH_INFO')
        excluded_paths = settings.ASAP_EXCLUDE_PATHS
        if any([excluded.match(path) for excluded in excluded_paths]):
            return

    try:
        if token is None:
            raise NoTokenProvidedError
        verifier = backend.get_verifier(settings=settings)
        asap_claims = verifier.verify_jwt(
            token,
            settings.ASAP_VALID_AUDIENCE,
            leeway=settings.ASAP_VALID_LEEWAY,
        )

        _verify_issuers(asap_claims, settings.ASAP_VALID_ISSUERS)
        backend.set_asap_claims_for_request(request, asap_claims)
    except NoTokenProvidedError:
        error_response = backend.get_401_response(
            'Unauthorized', request=request
        )
    except PublicKeyRetrieverException as e:
        if e.status_code not in (403, 404):
            # Any error other than "not found" is a problem and should
            # be dealt with elsewhere.
            # Note that we treat 403 like 404 to account for the fact
            # that a server configured to secure directory listings
            # will return 403 for a missing file to avoid leaking
            # information.
            raise

        error_response = backend.get_401_response(
            'Unauthorized: Key not found', request=request
        )
    except InvalidIssuerError:
        error_response = backend.get_403_response(
            'Forbidden: Invalid token issuer', request=request
        )
    except InvalidTokenError:
        error_response = backend.get_401_response(
            'Unauthorized: Invalid token', request=request
        )

    if error_response is not None and settings.ASAP_REQUIRED:
        return error_response


def _verify_issuers(asap_claims, issuers=None):
    """Verify that the issuer in the claims is valid and is expected."""
    claim_iss = asap_claims.get('iss')
    if issuers and claim_iss not in issuers:
        raise InvalidIssuerError
