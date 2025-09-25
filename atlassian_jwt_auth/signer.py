import calendar
import datetime
import random
from typing import Any, Dict, Iterable, Optional, Union

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from atlassian_jwt_auth import algorithms, key
from atlassian_jwt_auth.key import BasePrivateKeyRetriever, KeyIdentifier


class JWTAuthSigner(object):
    def __init__(
        self, issuer: str, private_key_retriever: BasePrivateKeyRetriever, **kwargs: Any
    ) -> None:
        self.issuer = issuer
        self.private_key_retriever = private_key_retriever
        self.lifetime = kwargs.get("lifetime", datetime.timedelta(minutes=1))
        self.algorithm = kwargs.get("algorithm", "RS256")
        self.subject = kwargs.get("subject", None)
        self._private_keys_cache: Dict[str, Any] = dict()

        if self.algorithm not in set(algorithms.get_permitted_algorithm_names()):
            raise ValueError("Algorithm, '%s', is not permitted." % self.algorithm)
        if self.lifetime > datetime.timedelta(hours=1):
            raise ValueError(
                "lifetime, '%s',exceeds the allowed 1 hour max" % (self.lifetime)
            )

    def _obtain_private_key(
        self, key_identifier: KeyIdentifier, private_key_pem: Union[str, bytes]
    ):
        """returns a loaded instance of the given private key either from
        cache or from the given private_key_pem.
        """
        priv_key = self._private_keys_cache.get(key_identifier.key_id, None)
        if priv_key is not None:
            return priv_key
        private_key_bytes: bytes
        if not isinstance(private_key_pem, bytes):
            private_key_bytes = private_key_pem.encode()
        else:
            private_key_bytes = private_key_pem
        priv_key = serialization.load_pem_private_key(
            private_key_bytes, password=None, backend=default_backend()
        )
        if len(self._private_keys_cache) > 10:
            self._private_keys_cache = dict()
        self._private_keys_cache[key_identifier.key_id] = priv_key
        return priv_key

    def _generate_claims(
        self, audience: Union[str, Iterable[str]], **kwargs: Any
    ) -> Dict[Any, Any]:
        """returns a new dictionary of claims."""
        now = self._now()
        claims = {
            "iss": self.issuer,
            "exp": now + self.lifetime,
            "iat": now,
            "aud": audience,
            "jti": "%s:%s"
            % (now.strftime("%s"), random.SystemRandom().getrandbits(32)),
            "nbf": now,
            "sub": self.subject or self.issuer,
        }
        claims.update(kwargs.get("additional_claims", {}))
        return claims

    def _now(self) -> datetime.datetime:
        return datetime.datetime.now(datetime.timezone.utc)

    def generate_jwt(self, audience: Union[str, Iterable[str]], **kwargs: Any) -> bytes:
        """returns a new signed jwt for use."""
        key_identifier, private_key_pem = self.private_key_retriever.load(self.issuer)
        private_key = self._obtain_private_key(key_identifier, private_key_pem)
        token: str = jwt.encode(
            self._generate_claims(audience, **kwargs),
            key=private_key,
            algorithm=self.algorithm,
            headers={
                "kid": key_identifier.key_id
                if isinstance(key_identifier, KeyIdentifier)
                else key_identifier
            },
        )
        return token.encode("utf-8")


class TokenReusingJWTAuthSigner(JWTAuthSigner):
    def __init__(
        self, issuer: str, private_key_retriever: BasePrivateKeyRetriever, **kwargs: Any
    ) -> None:
        super(TokenReusingJWTAuthSigner, self).__init__(
            issuer, private_key_retriever, **kwargs
        )
        self.reuse_threshold = kwargs.get("reuse_jwt_threshold", 0.95)

    def get_cached_token(
        self, audience: Union[str, Iterable[str]], **kwargs: Any
    ) -> Optional[bytes]:
        """returns the cached token. If there is no matching cached token
        then None is returned.
        """
        return getattr(self, "_previous_token", None)

    def set_cached_token(self, value: Any) -> None:
        """sets the cached token."""
        self._previous_token = value

    def can_reuse_token(self, existing_token, claims) -> bool:
        """returns True if the provided existing token can be reused
        for the claims provided.
        """
        if existing_token is None:
            return False
        existing_claims = jwt.decode(
            existing_token, options={"verify_signature": False}
        )
        existing_lifetime = int(existing_claims["exp"]) - int(existing_claims["iat"])
        this_lifetime = (claims["exp"] - claims["iat"]).total_seconds()
        if existing_lifetime != this_lifetime:
            return False
        about_to_expire = int(existing_claims["iat"]) + (
            self.reuse_threshold * existing_lifetime
        )
        if calendar.timegm(self._now().utctimetuple()) > about_to_expire:
            return False
        if set(claims.keys()) != set(existing_claims.keys()):
            return False
        for dict_key, val in claims.items():
            if dict_key in ["exp", "iat", "jti", "nbf"]:
                continue
            if existing_claims[dict_key] != val:
                return False
        return True

    def generate_jwt(self, audience: Union[str, Iterable[str]], **kwargs: Any) -> bytes:
        existing_token = self.get_cached_token(audience, **kwargs)
        claims = self._generate_claims(audience, **kwargs)
        if existing_token and self.can_reuse_token(existing_token, claims):
            return existing_token
        token = super(TokenReusingJWTAuthSigner, self).generate_jwt(audience, **kwargs)
        self.set_cached_token(token)
        return token


def _create_signer(
    issuer: str, private_key_retriever: BasePrivateKeyRetriever, **kwargs: Any
) -> JWTAuthSigner:
    signer_cls = JWTAuthSigner
    if kwargs.get("reuse_jwts", None):
        signer_cls = TokenReusingJWTAuthSigner
    return signer_cls(issuer, private_key_retriever, **kwargs)


def create_signer(
    issuer: str,
    key_identifier: Union[KeyIdentifier, str],
    private_key_pem: Union[str, bytes],
    **kwargs: Any,
) -> JWTAuthSigner:
    private_key_retriever = key.StaticPrivateKeyRetriever(
        key_identifier, private_key_pem
    )
    return _create_signer(issuer, private_key_retriever, **kwargs)


def create_signer_from_file_private_key_repository(
    issuer: str, private_key_repository: str, **kwargs: Any
) -> JWTAuthSigner:
    private_key_retriever = key.FilePrivateKeyRetriever(private_key_repository)
    return _create_signer(issuer, private_key_retriever, **kwargs)
