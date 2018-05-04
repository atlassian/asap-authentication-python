from atlassian_jwt_auth.exceptions import PublicKeyRetrieverException
from jwt.exceptions import InvalidIssuerError, InvalidTokenError
from .exceptions import NoTokenProvidedError, SubjectIssuerMismatchError


class SettingsDict(dict):
    def __getattr__(self, name):
        if name not in self:
            raise AttributeError

        return self[name]

    def __setitem__(self, key, value):
        raise AttributeError('SettingsDict properties are immutable')


def process_asap_token(request, backend, settings):
    verifier = backend.get_verifier()
    token = backend.get_asap_token(request)
    error_response = None

    try:
        asap_claims = _check_asap_token(
            token, verifier, settings
        )
        backend.set_asap_claims_for_request(request, asap_claims)
    except NoTokenProvidedError:
        error_response = backend.get_401_response('Unauthorized')
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
            'Unauthorized: Key not found'
        )
    except InvalidIssuerError:
        error_response = backend.get_403_response(
            'Forbidden: Invalid token issuer'
        )
    except InvalidTokenError:
        error_response = backend.get_401_response(
            'Unauthorized: Invalid token'
        )

    if error_response and settings.ASAP_REQUIRED:
        return error_response


def _check_asap_token(token, verifier, settings):
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

    return asap_claims


def _validate_claims(claims, settings):
    if (settings.ASAP_VALID_ISSUERS
            and claims.get('iss') not in settings.ASAP_VALID_ISSUERS):
        raise InvalidIssuerError

    if (settings.ASAP_SUBJECT_SHOULD_MATCH_ISSUER
            and claims.get('iss') != claims.get('sub')):
        raise SubjectIssuerMismatchError
