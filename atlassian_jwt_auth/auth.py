from __future__ import absolute_import
from datetime import datetime, timedelta

import atlassian_jwt_auth


class BaseJWTAuth(object):
    """Adds a JWT bearer token to the request per the ASAP specification"""
    def __init__(self, signer, audience, reuse_jwts=False,
                 reuse_jwt_threshold=0.95, *args, **kwargs):
        self._audience = audience
        self._signer = signer
        self._additional_claims = kwargs.get('additional_claims', {})
        self._reuse_jwts = reuse_jwts
        self._reuse_jwt_threshold = reuse_jwt_threshold
        self._encoded_jwt = None
        self._claims = None

    @classmethod
    def create(cls, issuer, key_identifier, private_key_pem, audience,
               reuse_jwts=None, reuse_jwt_threshold=None, **kwargs):
        """Instantiate a JWTAuth while creating the signer inline"""
        signer = atlassian_jwt_auth.create_signer(issuer, key_identifier,
                                                  private_key_pem, **kwargs)
        cls_kwargs = {}
        if reuse_jwts is not None:
            cls_kwargs['reuse_jwts'] = reuse_jwts
        if reuse_jwt_threshold is not None:
            cls_kwargs['reuse_jwt_threshold'] = reuse_jwt_threshold
        return cls(signer, audience, **cls_kwargs)

    def _get_header_value(self):
        if self._should_generate_jwt():
            self._encoded_jwt, self._claims = self._signer.generate_jwt(
                self._audience, additional_claims=self._additional_claims,
                return_claims=True)
        return b'Bearer ' + self._encoded_jwt

    def _should_generate_jwt(self):
        if not self._reuse_jwts or self._encoded_jwt is None:
            return True

        # Regenerate the JWT if it is about to expire
        return datetime.utcnow() > (self._claims['iat'] + timedelta(
            seconds=self._reuse_jwt_threshold *
            self._signer.lifetime.total_seconds()))
