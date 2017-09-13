import unittest

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


class RequestsRS256Test(BaseRequestsTest,
                        utils.RS256KeyTestMixin,
                        unittest.TestCase):
    pass


class RequestsES256Test(BaseRequestsTest,
                        utils.ES256KeyTestMixin,
                        unittest.TestCase):
    pass
