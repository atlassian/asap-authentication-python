import unittest

import jwt
from requests import Request

from atlassian_jwt_auth.tests import utils
from atlassian_jwt_auth.contrib.requests import create_jwt_auth


class RequestsTest(unittest.TestCase, utils.RS256KeyTestMixin):
    """ tests for the contrib.requests.JWTAuth class """

    def setUp(self):
        self._private_key_pem = self.get_new_private_key_in_pem_format()
        self._public_key_pem = utils.get_public_key_pem_for_private_key_pem(
            self._private_key_pem)

    def test_JWTAuth_make_authenticated_request(self):
        """Verify a valid Authorization header is added by JWTAuth"""
        auth = create_jwt_auth('issuer', 'issuer/key',
                               self._private_key_pem.decode(), 'audience')
        req = auth(Request())

        auth_header = req.headers['Authorization']
        bearer = auth_header.split(b' ')[1]

        # Decode the JWT (verifying the signature and aud match)
        # an exception is thrown if this fails
        jwt.decode(bearer, self._public_key_pem.decode(), audience='audience')
