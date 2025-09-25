from __future__ import absolute_import

from typing import Any, Iterable, Union

import atlassian_jwt_auth
from atlassian_jwt_auth import KeyIdentifier
from atlassian_jwt_auth.signer import JWTAuthSigner


class BaseJWTAuth(object):
    """Adds a JWT bearer token to the request per the ASAP specification"""

    def __init__(
        self,
        signer: JWTAuthSigner,
        audience: Union[str, Iterable[str]],
        *args: Any,
        **kwargs: Any,
    ) -> None:
        self._audience = audience
        self._signer = signer
        self._additional_claims = kwargs.get("additional_claims", {})

    @classmethod
    def create(
        cls,
        issuer: str,
        key_identifier: Union[KeyIdentifier, str],
        private_key_pem: Union[str, bytes],
        audience: Union[str, Iterable[str]],
        **kwargs: Any,
    ) -> "BaseJWTAuth":
        """Instantiate a JWTAuth while creating the signer inline"""
        signer = atlassian_jwt_auth.create_signer(
            issuer, key_identifier, private_key_pem, **kwargs
        )
        return cls(signer, audience)

    def _get_header_value(self) -> bytes:
        return b"Bearer " + self._signer.generate_jwt(
            self._audience, additional_claims=self._additional_claims
        )
