from collections import OrderedDict

import jwt
import jwt.api_jwt
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPublicKey
)
from jwt.exceptions import InvalidAlgorithmError

from atlassian_jwt_auth import algorithms
from atlassian_jwt_auth import key
from atlassian_jwt_auth import exceptions

try:
    from functools import lru_cache
except ImportError:
    from backports.functools_lru_cache import lru_cache


class JWTAuthVerifier(object):

    """ This class can be used to verify a JWT. """

    def __init__(self, public_key_retriever, **kwargs):
        self.public_key_retriever = public_key_retriever
        self.algorithms = algorithms.get_permitted_algorithm_names()
        self._seen_jti = OrderedDict()
        self._subject_should_match_issuer = kwargs.get(
            'subject_should_match_issuer', True)
        self._check_jti_uniqueness = kwargs.get(
            'check_jti_uniqueness', False)

    def verify_jwt(self, a_jwt, audience, leeway=0, **requests_kwargs):
        """Verify if the token is correct

        Returns:
             dict: the claims of the given jwt if verification is successful.

        Raises:
            ValueError: if verification failed.
        """
        key_identifier = key._get_key_id_from_jwt_header(a_jwt)
        public_key = self._retrieve_pub_key(key_identifier, requests_kwargs)
        public_key_obj = public_key
        if not isinstance(public_key, (RSAPublicKey, EllipticCurvePublicKey)):
            alg = jwt.get_unverified_header(a_jwt).get('alg', None)
            public_key_obj = self._load_public_key(public_key, alg)
        return self._decode_jwt(
            a_jwt, key_identifier, public_key_obj,
            audience=audience, leeway=leeway)

    def _retrieve_pub_key(self, key_identifier, requests_kwargs):
        return self.public_key_retriever.retrieve(
            key_identifier, **requests_kwargs)

    @lru_cache(maxsize=10)
    def _load_public_key(self, public_key, algorithm):
        """ Returns a public key object instance given the public key and
            algorithm.
        """
        if algorithm not in self.algorithms:
            raise InvalidAlgorithmError(
                'The specified alg value is not allowed')
        py_jwt = jwt.api_jwt.PyJWT(algorithms=self.algorithms)
        alg_obj = py_jwt._algorithms[algorithm]
        return alg_obj.prepare_key(public_key)

    def _decode_jwt(self, a_jwt, key_identifier, jwt_key,
                    audience=None, leeway=0):
        """Decode JWT and check if it's valid"""
        options = {
            'verify_signature': True,
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

    def _check_jti(self, jti):
        """Checks that the given jti has not been already been used."""
        if jti in self._seen_jti:
            raise exceptions.JtiUniquenessException(
                "The jti, '%s', has already been used." % jti)
        self._seen_jti[jti] = None
        while len(self._seen_jti) > 1000:
            self._seen_jti.popitem(last=False)
