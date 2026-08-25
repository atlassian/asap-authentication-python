from typing import Any

import atlassian_jwt_auth
from atlassian_jwt_auth import JWTAuthVerifier
from atlassian_jwt_auth.key import BasePublicKeyRetriever


def get_static_retriever_class(keys: dict[str, Any]) -> type[BasePublicKeyRetriever]:
    class StaticPublicKeyRetriever(BasePublicKeyRetriever):
        """Retrieves a key from a static dict of public keys
        (for use in tests only)"""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.keys: dict[str, Any] = keys

        def retrieve(self, key_identifier, **requests_kwargs) -> Any:
            return self.keys[key_identifier.key_id]

    return StaticPublicKeyRetriever


def static_verifier(keys: dict[str, Any]) -> JWTAuthVerifier:
    return atlassian_jwt_auth.JWTAuthVerifier(get_static_retriever_class(keys)())
