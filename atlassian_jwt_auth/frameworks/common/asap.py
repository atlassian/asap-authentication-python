from atlassian_jwt_auth.exceptions import PublicKeyRetrieverException
from jwt.exceptions import InvalidIssuerError, InvalidTokenError
from .exceptions import NoTokenProvidedError, SubjectIssuerMismatchError


def _process_asap_token(request, backend, settings):
    """ Verifies an ASAP token, validates the claims, and returns an error
    response"""
    verifier = backend.get_verifier()
    token = backend.get_asap_token(request)
    error_response = None

    try:
        if token is None:
            raise NoTokenProvidedError

        asap_claims = verifier.verify_jwt(
            token,
            settings.ASAP_VALID_AUDIENCE,
            leeway=settings.ASAP_VALID_LEEWAY,
        )

        _validate_claims(
            asap_claims, settings
        )

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
    except InvalidTokenError as ex:
        error_response = backend.get_401_response(
            'Unauthorized: Invalid token', request=request
        )

    if error_response is not None and settings.ASAP_REQUIRED:
        return error_response


def _validate_claims(claims, settings):
    """Validates a set of ASAP claims against ASAP-specific validation logic"""
    if (settings.ASAP_VALID_ISSUERS
            and claims.get('iss') not in settings.ASAP_VALID_ISSUERS):
        raise InvalidIssuerError

    if (settings.ASAP_SUBJECT_SHOULD_MATCH_ISSUER
            and claims.get('iss') != claims.get('sub')):
        raise SubjectIssuerMismatchError
