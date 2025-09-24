from typing import Any, Dict, Union

from aiohttp import BasicAuth

from atlassian_jwt_auth import KeyIdentifier
from atlassian_jwt_auth.auth import BaseJWTAuth


class JWTAuth(BaseJWTAuth, BasicAuth):
    """Adds a JWT bearer token to the request per the ASAP specification

    It should be aiohttp.BasicAuth subclass, so redefine its `__new__` method.
    """
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls, '')

    def encode(self) -> str:
        return self._get_header_value().decode(self.encoding)


def create_jwt_auth(
        issuer: str, key_identifier: Union[KeyIdentifier, str], private_key_pem: str, audience: str, **kwargs: Any) -> BaseJWTAuth:
    """Instantiate a JWTAuth while creating the signer inline"""
    return JWTAuth.create(
        issuer, key_identifier, private_key_pem, audience, **kwargs)
