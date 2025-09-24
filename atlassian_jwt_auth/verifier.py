from collections import OrderedDict
from functools import lru_cache
from typing import (TYPE_CHECKING, Any, Dict, Iterable, Optional, Sequence,
                    Union)

import jwt
import jwt.api_jwt
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt import PyJWK
from jwt.exceptions import InvalidAlgorithmError

from atlassian_jwt_auth import KeyIdentifier, algorithms, exceptions, key
from atlassian_jwt_auth.key import BasePublicKeyRetriever

AllowedPublicKeys = (RSAPublicKey | EllipticCurvePublicKey | Ed25519PublicKey | Ed448PublicKey)

@lru_cache(maxsize=10)
def _load_public_key(
        algorithms: Sequence[str], public_key: str, algorithm: Optional[str]) -> Any:
    """ Returns a public key object instance given the public key and
        algorithm.

        This has been extracted out of JWTAuthVerifier to avoid possible memory
        leaks via retained instance references.
    """
    if isinstance(public_key, (RSAPublicKey, EllipticCurvePublicKey)):
        return public_key
    if algorithm is None or algorithm not in algorithms:
        raise InvalidAlgorithmError(
            'The specified alg value is not allowed')
    py_jws = jwt.api_jws.PyJWS(algorithms=algorithms)
    alg_obj = py_jws._algorithms[algorithm]
    return alg_obj.prepare_key(public_key)


class JWTAuthVerifier(object):

    """ This class can be used to verify a JWT. """

    def __init__(self, public_key_retriever: BasePublicKeyRetriever,
                 **kwargs: Any) -> None:
        self.public_key_retriever = public_key_retriever
        self.algorithms = algorithms.get_permitted_algorithm_names()
        self._seen_jti: OrderedDict[str, None] = OrderedDict()
        self._subject_should_match_issuer = kwargs.get(
            'subject_should_match_issuer', True)
        self._check_jti_uniqueness = kwargs.get(
            'check_jti_uniqueness', False)

    def verify_jwt(self, a_jwt: str, audience: str, leeway: int = 0,
                   **requests_kwargs: Any) -> Dict[Any, Any]:
        """Verify if the token is correct

        Returns:
             dict: the claims of the given jwt if verification is successful.

        Raises:
            ValueError: if verification failed.
        """
        key_identifier = key._get_key_id_from_jwt_header(a_jwt)
        public_key = self._retrieve_pub_key(key_identifier, requests_kwargs)

        alg = jwt.get_unverified_header(a_jwt).get('alg', None)
        public_key_obj = self._load_public_key(public_key, alg or 'RS256')
        return self._decode_jwt(
            a_jwt, key_identifier, public_key_obj,
            audience=audience, leeway=leeway)

    def _retrieve_pub_key(
            self, key_identifier: Union[KeyIdentifier, str], requests_kwargs: Any) -> str:
        return self.public_key_retriever.retrieve(
            key_identifier, **requests_kwargs)

    def _load_public_key(self, public_key: str, algorithm: Optional[str]) -> Any:
        """ Returns a public key object instance given the public key and
            algorithm.
        """
        return _load_public_key(tuple(self.algorithms), public_key, algorithm)

    def _decode_jwt(self, a_jwt: str, key_identifier: KeyIdentifier, jwt_key: AllowedPublicKeys | PyJWK | str | bytes,
                    audience: str | Iterable[str] | None=None, leeway: int = 0) -> Dict[Any, Any]:
        """Decode JWT and check if it's valid"""
        options = {
            'verify_signature': True,
            'require': ['exp', 'iat'],
            'require_exp': True,
            'require_iat': True,
        }

        claims = jwt.decode(
            a_jwt,
            key=jwt_key,
            algorithms=self.algorithms,
            options=options,
            audience=audience,
            leeway=leeway)

        if (not key_identifier.key_id.startswith('%s/' % claims['iss']) and
                key_identifier.key_id != claims['iss']):
            raise ValueError('Issuer does not own the supplied public key')

        if self._subject_should_match_issuer and (
                claims.get('sub') and claims['iss'] != claims['sub']):
            raise exceptions.SubjectDoesNotMatchIssuerException(
                'Issuer does not match the subject.')

        _aud = claims.get('aud', None)
        if _aud is None:
            _msg = ("Claims validity, the aud claim must be provided and "
                    "cannot be empty.")
            raise KeyError(_msg)
        _exp = int(claims['exp'])
        _iat = int(claims['iat'])
        if _exp - _iat > 3600:
            _msg = ("Claims validity, '%s', exceeds the maximum 1 hour." %
                    (_exp - _iat))
            raise ValueError(_msg)
        _jti = claims['jti']
        if self._check_jti_uniqueness:
            self._check_jti(_jti)
        return claims

    def _check_jti(self, jti: str) -> None:
        """Checks that the given jti has not been already been used."""
        if jti in self._seen_jti:
            raise exceptions.JtiUniquenessException(
                "The jti, '%s', has already been used." % jti)
        self._seen_jti[jti] = None
        while len(self._seen_jti) > 1000:
            self._seen_jti.popitem(last=False)
