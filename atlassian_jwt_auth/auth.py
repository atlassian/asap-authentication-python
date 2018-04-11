from __future__ import absolute_import
from datetime import datetime, timedelta

import atlassian_jwt_auth

# Regenerate the JWT token once 95% of its valid time window has passed
_DEFAULT_REUSE_JWT_THRESHOLD = 0.95


class BaseJWTAuth(object):
    """Adds a JWT bearer token to the request per the ASAP specification"""
    def __init__(self, signer, audience, reuse_jwts=False,
                 reuse_jwt_threshold=_DEFAULT_REUSE_JWT_THRESHOLD, *args,
                 **kwargs):
        self._audience = audience
        self._signer = signer
        self._additional_claims = kwargs.get('additional_claims', {})
        self._reuse_jwts = reuse_jwts
        self._reuse_jwt_threshold = reuse_jwt_threshold
        self._encoded_jwt = None
        self._claims = None

    @classmethod
    def create(cls, issuer, key_identifier, private_key_pem, audience,
               reuse_jwts=False,
               reuse_jwt_threshold=_DEFAULT_REUSE_JWT_THRESHOLD, **kwargs):
        """Instantiate a JWTAuth while creating the signer inline"""
        signer = atlassian_jwt_auth.create_signer(issuer, key_identifier,
                                                  private_key_pem, **kwargs)
        return cls(signer, audience, reuse_jwts=reuse_jwts,
                   reuse_jwt_threshold=reuse_jwt_threshold)

    def _get_header_value(self):
        if self._should_generate_jwt():
            self._encoded_jwt, self._claims = self._signer.generate_jwt(
                self._audience, additional_claims=self._additional_claims,
                return_claims=True)
        return b'Bearer ' + self._encoded_jwt

    def _should_generate_jwt(self):
        if not self._reuse_jwts or self._encoded_jwt is None:
            return True

        # Rengerate the JWT if it is about to expire
        return datetime.utcnow() > (self._claims['iat'] + timedelta(
            seconds=self._reuse_jwt_threshold *
            self._signer.lifetime.total_seconds()))
