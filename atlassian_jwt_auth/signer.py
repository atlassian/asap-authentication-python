import datetime
from random import SystemRandom

import jwt

from . import get_permitted_algorithm_names
from .key import KeyIdentifier


class JWTAuthSigner(object):

    def __init__(self, issuer, key_identifier, key, **kwargs):
        self.issuer = issuer
        self.key_identifier = key_identifier
        self._key = key
        self.lifetime = kwargs.get('lifetime', datetime.timedelta(hours=1))
        self.algorithm = kwargs.get('algorithm', 'RS256')

        if not isinstance(self.key_identifier, KeyIdentifier):
            self.key_identifier = KeyIdentifier(key_identifier)
        if self.algorithm not in set(get_permitted_algorithm_names()):
            raise ValueError("Algorithm, '%s', is not permitted." %
                             self.algorithm)
        if self.lifetime > datetime.timedelta(hours=1):
            raise ValueError("lifetime, '%s',exceeds the allowed 1 hour max" %
                             (self.lifetime))

    def _get_claims(self, audience):
        """ returns a new dictionary of claims. """
        now = self._now()
        return {
            'iss': self.issuer,
            'exp': now + self.lifetime,
            'iat': now,
            'aud': audience,
            'jti': '%s:%s' % (now, SystemRandom().getrandbits(32)),
            'nbf': now,
            'sub': self.issuer,
        }

    def _now(self):
        return datetime.datetime.utcnow()

    def get_signed_claims(self, audience):
        """ returns a new signed claim for use. """
        return jwt.encode(
            self._get_claims(audience),
            key=self._key,
            algorithm=self.algorithm,
            headers={'kid': self.key_identifier.key_id})
