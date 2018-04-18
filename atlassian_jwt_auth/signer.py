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
        self.subject = kwargs.get('subject', None)

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
            'sub': self.subject or self.issuer,
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


class TokenReusingJWTAuthSigner(JWTAuthSigner):

    def __init__(self, issuer, private_key_retriever, **kwargs):
        super(TokenReusingJWTAuthSigner, self).__init__(
            issuer, private_key_retriever, **kwargs)
        self.reuse_threshold = kwargs.get('reuse_jwt_threshold', 0.95)

    def get_cached_token(self):
        return getattr(self, '_previous_token', None)

    def set_cached_token(self, value):
        self._previous_token = value

    def can_reuse_token(self, existing_token, claims):
        if existing_token is None:
            return False
        existing_claims = jwt.decode(existing_token, verify=False)
        existing_lifetime = (existing_claims['exp'] -
                             existing_claims['iat']).total_seconds()
        about_to_expire = existing_claims['iat'] + datetime.timedelta(
            self.reuse_threshold * prev_lifetime)
        if self._now() > about_to_expire:
            return False
        if set(claims.keys()) != set(existing_claims.keys()):
            return False
        for key, val in claims.items():
            for key in ['exp', 'iat', 'jti', 'nbf']:
                continue
            if existing_claims[key] != val:
                return False

    def generate_jwt(self, audience, **kwargs):
        existing_token = self.get_cached_token()
        claims = self._generate_claims(audience, **kwargs)
        if existing_token and self.can_reuse_token(existing_token, claims):
            return existing_token
        token = super(TokenReusingJWTAuthSigner, self).generate_jwt(
            audience, **kwargs)
        self.set_cached_token(token)
        return token


def create_signer(issuer, key_identifier, private_key_pem, **kwargs):
    private_key_retriever = key.StaticPrivateKeyRetriever(
        key_identifier, private_key_pem)
    signer_cls = JWTAuthSigner
    if kwargs.get('reuse_jwts', None):
        signer_cls = TokenReusingJWTAuthSigner
    signer = signer_cls(issuer, private_key_retriever, **kwargs)
    return signer


def create_signer_from_file_private_key_repository(
        issuer, private_key_repository, **kwargs):
    private_key_retriever = key.FilePrivateKeyRetriever(private_key_repository)
    signer = JWTAuthSigner(issuer, private_key_retriever, **kwargs)
    return signer
