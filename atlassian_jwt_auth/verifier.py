import jwt

from atlassian_jwt_auth import algorithms
from atlassian_jwt_auth import key


class JWTAuthVerifier(object):

    """ This class can be used to verify a JWT. """

    def __init__(self, public_key_retriever, **kwargs):
        self.public_key_retriever = public_key_retriever
        self.algorithms = algorithms.get_permitted_algorithm_names()
        self._seen_jti = set()
        self._subject_should_match_issuer = kwargs.get(
            'subject_should_match_issuer', True)

    def verify_jwt(self, a_jwt, audience, leeway=0, **requests_kwargs):
        """ returns the claims of the given jwt iff verification
            is successful.
        """
        options = {
            'verify_signature': True,
            'require_exp': True,
            'require_iat': True,
        }
        key_identifier = key._get_key_id_from_jwt_header(a_jwt)
        public_key = self.public_key_retriever.retrieve(
            key_identifier, **requests_kwargs)
        claims = jwt.decode(
            a_jwt, key=public_key,
            algorithms=self.algorithms,
            options=options,
            audience=audience,
            leeway=leeway)
        if not (key_identifier.key_id.startswith('%s/' % claims['iss']) or
                key_identifier.key_id == claims['iss']):
            raise ValueError('Issuer does not own the supplied public key')
        if self._subject_should_match_issuer and (
                claims.get('sub') and claims['iss'] != claims['sub']):
            raise ValueError('Issuer does not match the subject.')
        _aud = claims['aud']
        _exp = int(claims['exp'])
        _iat = int(claims['iat'])
        if _exp - _iat > 3600:
            _msg = ("Claims validity, '%s', exceeds the maximum 1 hour." %
                    (_exp - _iat))
            raise ValueError(_msg)
        _jti = claims['jti']
        if _jti in self._seen_jti:
            raise ValueError("The jti, '%s', has already been used." % _jti)
        else:
            if len(self._seen_jti) > 100:
                self._seen_jti = set()
            self._seen_jti.add(_jti)
        return claims
