from __future__ import absolute_import
from datetime import datetime, timedelta

import atlassian_jwt_auth


class TokenReusePolicy(object):
    def cache_token(self, encoded_jwt, claims):
        pass

    def get_cached_token(self):
        return None


class NeverReuseTokens(TokenReusePolicy):
    pass


class ReuseTokens(TokenReusePolicy):
    _default_threshold = 0.95

    def __init__(self, threshold=None):
        self._threshold = threshold or self._default_threshold
        self._encoded_jwt = None
        self._claims = None

    def cache_token(self, encoded_jwt, claims):
        self._encoded_jwt = encoded_jwt
        self._claims = claims

    def get_cached_token(self):
        if self._encoded_jwt is None:
            return None
        lifetime = (self._claims['exp'] - self._claims['iat']).total_seconds()
        about_to_expire = (self._claims['iat'] +
                           timedelta(seconds=self._threshold * lifetime))
        if datetime.utcnow() > about_to_expire:
            self._encoded_jwt = None
            self._claims = None
            return None
        return self._encoded_jwt


class BaseJWTAuth(object):
    """Adds a JWT bearer token to the request per the ASAP specification"""
    def __init__(self, signer, audience, reuse_policy=None, *args,
                 **kwargs):
        self._audience = audience
        self._signer = signer
        self._additional_claims = kwargs.get('additional_claims', {})
        self._reuse_policy = reuse_policy or NeverReuseTokens()

    @classmethod
    def create(cls, issuer, key_identifier, private_key_pem, audience,
               reuse_jwts=False, reuse_jwt_threshold=None, **kwargs):
        """Instantiate a JWTAuth while creating the signer inline"""
        signer = atlassian_jwt_auth.create_signer(issuer, key_identifier,
                                                  private_key_pem, **kwargs)
        cls_kwargs = {}
        if reuse_jwts:
            cls_kwargs['reuse_policy'] = ReuseTokens(reuse_jwt_threshold)
        return cls(signer, audience, **cls_kwargs)

    def _get_header_value(self):
        encoded_jwt = self._reuse_policy.get_cached_token()
        if encoded_jwt is None:
            encoded_jwt, claims = self._signer.generate_jwt(
                self._audience, additional_claims=self._additional_claims)
            self._reuse_policy.cache_token(encoded_jwt, claims)
        return b'Bearer ' + encoded_jwt
