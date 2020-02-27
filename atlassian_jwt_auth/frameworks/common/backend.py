from abc import ABCMeta, abstractmethod, abstractproperty
try:
    from functools import lru_cache
except ImportError:
    from backports.functools_lru_cache import lru_cache

from atlassian_jwt_auth import HTTPSPublicKeyRetriever, JWTAuthVerifier

from jwt.compat import text_type
from .utils import SettingsDict


class Backend():
    """Abstract class representing a web framework backend

    Backends allow specific implementation details of web frameworks to be
    abstracted away from the underlying logic of ASAP.
    """
    __metaclass__ = ABCMeta

    default_headers_401 = {'WWW-Authenticate': 'Bearer'}
    default_settings = {
        # The class to be instantiated to retrieve public keys
        'ASAP_KEY_RETRIEVER_CLASS': HTTPSPublicKeyRetriever,

        # The repository URL where the key retriever can fetch public keys
        'ASAP_PUBLICKEY_REPOSITORY': None,

        # Whether or not ASAP authentication is required
        # This is primarily useful when phasing in ASAP authentication
        'ASAP_REQUIRED': True,

        # The valid audience value expected when authenticating tokens
        'ASAP_VALID_AUDIENCE': None,

        # The amount of leeway to apply when evaluating token expiration
        # timestamps
        'ASAP_VALID_LEEWAY': 0,

        # An iterable of valid token issuers allowed to authenticate
        # (this can be overridden at the decorator level)
        'ASAP_VALID_ISSUERS': None,

        # Enforce that the ASAP subject must match the issuer
        'ASAP_SUBJECT_SHOULD_MATCH_ISSUER': None,

        # Enforce that tokens have a unique JTI
        # Set this to True to enforce JTI uniqueness checking.
        'ASAP_CHECK_JTI_UNIQUENESS': None,
    }

    @abstractmethod
    def get_authorization_header(self, request=None):
        pass

    @abstractmethod
    def get_401_response(self, data=None, headers=None, request=None):
        pass

    @abstractmethod
    def get_403_response(self, data=None, headers=None, request=None):
        pass

    @abstractmethod
    def set_asap_claims_for_request(self, request, claims):
        pass

    @abstractproperty
    def settings(self):
        return SettingsDict(self.default_settings)

    def get_asap_token(self, request):
        auth_header = self.get_authorization_header(request)

        if auth_header is None:
            return None

        if isinstance(auth_header, text_type):
            # Per PEP-3333, headers must be in ISO-8859-1 or use an RFC-2047
            # MIME encoding. We don't really care about MIME encoded
            # headers, but some libraries allow sending bytes (Django tests)
            # and some (requests) always send str so we need to convert if
            # that is the case to properly support Python 3.
            auth_header = auth_header.encode(encoding='iso-8859-1')

        auth_values = auth_header.split(b' ')
        if len(auth_values) != 2 or auth_values[0].lower() != b'bearer':
            return None

        return auth_values[1]

    def get_verifier(self, settings=None):
        """Returns a verifier for ASAP JWT tokens"""
        if settings is None:
            settings = self.settings
        return self._get_verifier(settings)

    @lru_cache(maxsize=20)
    def _get_verifier(self, settings):
        retriever = settings.ASAP_KEY_RETRIEVER_CLASS(
            base_url=settings.ASAP_PUBLICKEY_REPOSITORY
        )
        kwargs = {}
        if settings.ASAP_SUBJECT_SHOULD_MATCH_ISSUER is not None:
            kwargs = {'subject_should_match_issuer':
                      settings.ASAP_SUBJECT_SHOULD_MATCH_ISSUER}
        if settings.ASAP_CHECK_JTI_UNIQUENESS is not None:
            kwargs['check_jti_uniqueness'] = settings.ASAP_CHECK_JTI_UNIQUENESS
        return JWTAuthVerifier(
            retriever,
            **kwargs
        )

    def _process_settings(self, settings):
        valid_issuers = settings.get('ASAP_VALID_ISSUERS')
        if valid_issuers:
            settings['ASAP_VALID_ISSUERS'] = set(valid_issuers)

        return SettingsDict(settings)
