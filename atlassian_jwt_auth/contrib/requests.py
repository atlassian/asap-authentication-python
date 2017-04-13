from __future__ import absolute_import

from atlassian_jwt_auth.auth import BaseJWTAuth

from requests.auth import AuthBase


class JWTAuth(AuthBase, BaseJWTAuth):
    """Adds a JWT bearer token to the request per the ASAP specification"""

    def __call__(self, r):
        r.headers['Authorization'] = self._get_header_value()
        return r


def create_jwt_auth(
        issuer, key_identifier, private_key_pem, audience, **kwargs):
    """Instantiate a JWTAuth while creating the signer inline"""
    return JWTAuth.create(
        issuer, key_identifier, private_key_pem, audience, **kwargs)
