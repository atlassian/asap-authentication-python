import unittest

import jwt
from requests import Request

import atlassian_jwt_auth
from atlassian_jwt_auth.tests import utils
from atlassian_jwt_auth.contrib.requests import JWTAuth, create_jwt_auth


class BaseRequestsTest(object):

    """ tests for the contrib.requests.JWTAuth class """

    def setUp(self):
        self._private_key_pem = self.get_new_private_key_in_pem_format()
        self._public_key_pem = utils.get_public_key_pem_for_private_key_pem(
            self._private_key_pem)

    def assert_authorization_header_is_valid(self, request):
        """ asserts that the given request contains a valid Authorization
            header.
        """
        auth_header = request.headers['Authorization']
        bearer = auth_header.split(b' ')[1]
        # Decode the JWT (verifying the signature and aud match)
        # an exception is thrown if this fails
        jwt.decode(bearer, self._public_key_pem.decode(), audience='audience')

    def test_JWTAuth_make_authenticated_request(self):
        """Verify a valid Authorization header is added by JWTAuth"""
        jwt_auth_signer = atlassian_jwt_auth.create_signer(
            'issuer',
            'issuer/key',
            self._private_key_pem.decode(),
            algorithm=self.algorithm)
        auth = JWTAuth(jwt_auth_signer, 'audience')
        req = auth(Request())
        self.assert_authorization_header_is_valid(req)

    def test_create_jwt_auth(self):
        """Verify a valid Authorization header is added by JWTAuth"""
        auth = create_jwt_auth('issuer', 'issuer/key',
                               self._private_key_pem.decode(), 'audience',
                               algorithm=self.algorithm)
        req = auth(Request())
        self.assert_authorization_header_is_valid(req)


class RequestsRS256Test(BaseRequestsTest,
                        utils.RS256KeyTestMixin,
                        unittest.TestCase):
    pass


class RequestsES256Test(BaseRequestsTest,
                        utils.ES256KeyTestMixin,
                        unittest.TestCase):
    pass
