from __future__ import absolute_import

import atlassian_jwt_auth


class BaseJWTAuth(object):
    """Adds a JWT bearer token to the request per the ASAP specification"""

    def __init__(self, signer, audience, *args, **kwargs):
        self._audience = audience
        self._signer = signer
        self._additional_claims = kwargs.get('additional_claims', {})

    @classmethod
    def create(cls, issuer, key_identifier, private_key_pem, audience,
               **kwargs):
        """Instantiate a JWTAuth while creating the signer inline"""
        signer = atlassian_jwt_auth.create_signer(issuer, key_identifier,
                                                  private_key_pem, **kwargs)
        return cls(signer, audience)

    def _get_header_value(self):
        return b'Bearer ' + self._signer.generate_jwt(
            self._audience, additional_claims=self._additional_claims)
