import datetime
import random

import jwt

from atlassian_jwt_auth import algorithms
from atlassian_jwt_auth import key


class JWTAuthSigner(object):

    def __init__(self, issuer, private_key_retriever, **kwargs):
        self.issuer = issuer
        self.private_key_retriever = private_key_retriever
        self.lifetime = kwargs.get('lifetime', datetime.timedelta(hours=1))
        self.algorithm = kwargs.get('algorithm', 'RS256')

        if self.algorithm not in set(
                algorithms.get_permitted_algorithm_names()):
            raise ValueError("Algorithm, '%s', is not permitted." %
                             self.algorithm)
        if self.lifetime > datetime.timedelta(hours=1):
            raise ValueError("lifetime, '%s',exceeds the allowed 1 hour max" %
                             (self.lifetime))

    def _generate_claims(self, audience, **kwargs):
        """ returns a new dictionary of claims. """
        now = self._now()
        claims = {
            'iss': self.issuer,
            'exp': now + self.lifetime,
            'iat': now,
            'aud': audience,
            'jti': '%s:%s' % (
                now.strftime('%s'), random.SystemRandom().getrandbits(32)),
            'nbf': now,
            'sub': self.issuer,
        }
        claims.update(kwargs.get('additional_claims', {}))
        return claims

    def _now(self):
        return datetime.datetime.utcnow()

    def generate_jwt(self, audience, **kwargs):
        """ returns a new signed jwt for use. """
        key_identifier, private_key_pem = self.private_key_retriever.load(
            self.issuer)
        return jwt.encode(
            self._generate_claims(audience, **kwargs),
            key=private_key_pem,
            algorithm=self.algorithm,
            headers={'kid': key_identifier.key_id})


def create_signer(issuer, key_identifier, private_key_pem, **kwargs):
    private_key_retriever = key.StaticPrivateKeyRetriever(
        key_identifier, private_key_pem)
    signer = JWTAuthSigner(issuer, private_key_retriever, **kwargs)
    return signer


def create_signer_from_file_private_key_repository(
        issuer, private_key_repository, **kwargs):
    private_key_retriever = key.FilePrivateKeyRetriever(private_key_repository)
    signer = JWTAuthSigner(issuer, private_key_retriever, **kwargs)
    return signer
