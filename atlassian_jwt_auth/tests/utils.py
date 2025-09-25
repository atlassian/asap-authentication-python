from typing import Any, Iterable, Optional, Protocol, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

import atlassian_jwt_auth
from atlassian_jwt_auth import KeyIdentifier
from atlassian_jwt_auth.signer import JWTAuthSigner


def get_new_rsa_private_key_in_pem_format() -> bytes:
    """returns a new rsa key in pem format."""
    private_key = rsa.generate_private_key(
        key_size=2048, backend=default_backend(), public_exponent=65537
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def get_public_key_pem_for_private_key_pem(private_key_pem: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None, backend=default_backend()
    )
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def get_example_jwt_auth_signer(**kwargs: Any) -> JWTAuthSigner:
    """returns an example jwt_auth_signer instance."""
    issuer = kwargs.get("issuer", "egissuer")
    key_id = kwargs.get("key_id", "%s/a" % issuer)
    key = kwargs.get("private_key_pem", get_new_rsa_private_key_in_pem_format())
    algorithm = kwargs.get("algorithm", "RS256")
    return atlassian_jwt_auth.create_signer(issuer, key_id, key, algorithm=algorithm)


def create_token(
    issuer: str,
    audience: Union[str, Iterable[str]],
    key_id: Union[KeyIdentifier, str],
    private_key: str,
    subject: Optional[str] = None,
):
    """ " returns a token based upon the supplied parameters."""
    signer = atlassian_jwt_auth.create_signer(
        issuer, key_id, private_key, subject=subject
    )
    return signer.generate_jwt(audience)


class BaseJWTAlgorithmTestMixin(object):
    """A mixin class to make testing different support for different
    jwt algorithms easier.
    """

    def get_new_private_key_in_pem_format(self) -> bytes:
        """returns a new private key in pem format."""
        raise NotImplementedError("not implemented.")


class UnitTestProtocol(Protocol):
    def assertEqual(self, a, b): ...

    def assertIsNotNone(self, a): ...

    def assertTrue(self, a): ...

    def assertIn(self, a, b): ...

    def assertNotEqual(self, a, b): ...


class KeyMixInProtocol(Protocol):
    @property
    def algorithm(self) -> str: ...

    def get_new_private_key_in_pem_format(self) -> bytes: ...


class RS256KeyTestMixin(KeyMixInProtocol):
    """Private rs256 test mixin."""

    @property
    def algorithm(self) -> str:
        return "RS256"

    def get_new_private_key_in_pem_format(self):
        return get_new_rsa_private_key_in_pem_format()


class ES256KeyTestMixin(KeyMixInProtocol):
    """Private es256 test mixin."""

    @property
    def algorithm(self) -> str:
        return "ES256"

    def get_new_private_key_in_pem_format(self):
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
