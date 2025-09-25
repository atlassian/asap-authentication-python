from typing import Any, Dict, Type


import atlassian_jwt_auth
from atlassian_jwt_auth import JWTAuthVerifier
from atlassian_jwt_auth.key import BasePublicKeyRetriever


def get_static_retriever_class(keys: Dict[str, Any]) -> Type[BasePublicKeyRetriever]:
    class StaticPublicKeyRetriever(BasePublicKeyRetriever):
        """Retrieves a key from a static dict of public keys
        (for use in tests only)"""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.keys: Dict[str, Any] = keys

        def retrieve(self, key_identifier, **requests_kwargs) -> Any:
            return self.keys[key_identifier.key_id]

    return StaticPublicKeyRetriever


def static_verifier(keys: Dict[str, Any]) -> JWTAuthVerifier:
    return atlassian_jwt_auth.JWTAuthVerifier(get_static_retriever_class(keys)())
