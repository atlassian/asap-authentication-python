from __future__ import absolute_import

from typing import Any, Union

import requests
from requests.auth import AuthBase

from atlassian_jwt_auth import KeyIdentifier
from atlassian_jwt_auth.auth import BaseJWTAuth


class JWTAuth(AuthBase, BaseJWTAuth):
    """Adds a JWT bearer token to the request per the ASAP specification"""

    def __call__(
        self, r: requests.models.PreparedRequest
    ) -> requests.models.PreparedRequest:
        r.headers["Authorization"] = self._get_header_value()  # type: ignore[assignment]
        return r


def create_jwt_auth(
    issuer: str,
    key_identifier: Union[KeyIdentifier, str],
    private_key_pem: str,
    audience: str,
    **kwargs: Any,
):
    """Instantiate a JWTAuth while creating the signer inline"""
    return JWTAuth.create(issuer, key_identifier, private_key_pem, audience, **kwargs)
