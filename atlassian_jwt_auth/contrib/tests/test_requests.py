import unittest
from datetime import timedelta

import jwt
from requests import Request

import atlassian_jwt_auth
from atlassian_jwt_auth.tests import utils
from atlassian_jwt_auth.contrib.requests import JWTAuth, create_jwt_auth


class BaseRequestsTest(object):

    """ tests for the contrib.requests.JWTAuth class """
    auth_cls = JWTAuth

    def setUp(self):
        self._private_key_pem = self.get_new_private_key_in_pem_format()
        self._public_key_pem = utils.get_public_key_pem_for_private_key_pem(
            self._private_key_pem)

    def assert_authorization_header_is_valid(self, auth):
        """ asserts that the given request contains a valid Authorization
            header.
        """
        auth_header = self._get_auth_header(auth)
        bearer = auth_header.split(b' ')[1]
        # Decode the JWT (verifying the signature and aud match)
        # an exception is thrown if this fails
        algorithms = atlassian_jwt_auth.get_permitted_algorithm_names()
        return jwt.decode(bearer, self._public_key_pem.decode(),
                          audience='audience', algorithms=algorithms)

    def _get_auth_header(self, auth):
        request = auth(Request())
        auth_header = request.headers['Authorization']
        return auth_header

    def create_jwt_auth(self, *args, **kwargs):
        return create_jwt_auth(*args, **kwargs)

    def test_JWTAuth_make_authenticated_request(self):
        """Verify a valid Authorization header is added by JWTAuth"""
        jwt_auth_signer = atlassian_jwt_auth.create_signer(
            'issuer',
            'issuer/key',
            self._private_key_pem.decode(),
            algorithm=self.algorithm)
        auth = self.auth_cls(jwt_auth_signer, 'audience')
        self.assert_authorization_header_is_valid(auth)

    def test_create_jwt_auth(self):
        """Verify a valid Authorization header is added by JWTAuth"""
        auth = self.create_jwt_auth('issuer', 'issuer/key',
                                    self._private_key_pem.decode(), 'audience',
                                    algorithm=self.algorithm)
        self.assert_authorization_header_is_valid(auth)

    def test_create_jwt_auth_with_additional_claims(self):
        """ Verify a Valid Authorization header is added by JWTAuth and
            contains the additional claims when provided.
        """
        jwt_auth_signer = atlassian_jwt_auth.create_signer(
            'issuer',
            'issuer/key',
            self._private_key_pem.decode(),
            algorithm=self.algorithm)
        auth = self.auth_cls(jwt_auth_signer, 'audience',
                             additional_claims={'example': 'claim'})
        token = self.assert_authorization_header_is_valid(auth)
        self.assertEqual(token.get('example'), 'claim')

    def test_do_not_reuse_jwts(self):
        auth = self.create_jwt_auth('issuer', 'issuer/key',
                                    self._private_key_pem.decode(), 'audience',
                                    algorithm=self.algorithm)
        auth_header = self._get_auth_header(auth)
        self.assertNotEqual(auth_header, self._get_auth_header(auth))

    def test_reuse_jwts(self):
        auth = self.create_jwt_auth('issuer', 'issuer/key',
                                    self._private_key_pem.decode(), 'audience',
                                    algorithm=self.algorithm, reuse_jwts=True)
        auth_header = self._get_auth_header(auth)
        self.assertEqual(auth_header, self._get_auth_header(auth))

    def test_do_not_reuse_jwt_if_audience_changes(self):
        auth = self.create_jwt_auth('issuer', 'issuer/key',
                                    self._private_key_pem.decode(), 'audience',
                                    algorithm=self.algorithm, reuse_jwts=True)
        auth_header = self._get_auth_header(auth)
        auth._audience = 'not-' + auth._audience
        self.assertNotEqual(auth_header, self._get_auth_header(auth))

    def test_do_not_reuse_jwt_if_issuer_changes(self):
        auth = self.create_jwt_auth('issuer', 'issuer/key',
                                    self._private_key_pem.decode(), 'audience',
                                    algorithm=self.algorithm, reuse_jwts=True)
        auth_header = self._get_auth_header(auth)
        auth._signer.issuer = 'not-' + auth._signer.issuer
        self.assertNotEqual(auth_header, self._get_auth_header(auth))

    def test_do_not_reuse_jwt_if_lifetime_changes(self):
        auth = self.create_jwt_auth('issuer', 'issuer/key',
                                    self._private_key_pem.decode(), 'audience',
                                    algorithm=self.algorithm, reuse_jwts=True)
        auth_header = self._get_auth_header(auth)
        auth._signer.lifetime = auth._signer.lifetime - timedelta(seconds=1)
        self.assertNotEqual(auth_header, self._get_auth_header(auth))

    def test_do_not_reuse_jwt_if_subject_changes(self):
        auth = self.create_jwt_auth('issuer', 'issuer/key',
                                    self._private_key_pem.decode(), 'audience',
                                    algorithm=self.algorithm, reuse_jwts=True,
                                    subject='subject')
        auth_header = self._get_auth_header(auth)
        auth._signer.subject = 'not-' + auth._signer.subject
        self.assertNotEqual(auth_header, self._get_auth_header(auth))

    def test_do_not_reuse_jwt_if_additional_claims_change(self):
        auth = self.create_jwt_auth('issuer', 'issuer/key',
                                    self._private_key_pem.decode(), 'audience',
                                    algorithm=self.algorithm, reuse_jwts=True)
        auth_header = self._get_auth_header(auth)
        auth._additional_claims['foo'] = 'bar'
        self.assertNotEqual(auth_header, self._get_auth_header(auth))

    def test_reuse_jwt_with_additional_claims(self):
        # calculating the cache key with additional claims is non-trivial
        auth = self.create_jwt_auth('issuer', 'issuer/key',
                                    self._private_key_pem.decode(), 'audience',
                                    algorithm=self.algorithm, reuse_jwts=True)
        auth._additional_claims['foo'] = 'bar'
        auth._additional_claims['fool'] = 'blah'
        auth._additional_claims['foot'] = 'quux'
        auth_header = self._get_auth_header(auth)
        self.assertEqual(auth_header, self._get_auth_header(auth))


class RequestsRS256Test(BaseRequestsTest,
                        utils.RS256KeyTestMixin,
                        unittest.TestCase):
    pass


class RequestsES256Test(BaseRequestsTest,
                        utils.ES256KeyTestMixin,
                        unittest.TestCase):
    pass
