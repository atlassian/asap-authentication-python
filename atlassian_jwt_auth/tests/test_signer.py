import datetime
import unittest

import mock

import atlassian_jwt_auth
from atlassian_jwt_auth.tests import utils


class BaseJWTAuthSignerTest(object):

    """ tests for the JWTAuthSigner class. """

    def setUp(self):
        self._private_key_pem = self.get_new_private_key_in_pem_format()

    def test__generate_claims(self):
        """ tests that _generate_claims works as expected. """
        expected_now = datetime.datetime(year=2001, day=1, month=1)
        expected_audience = 'example_aud'
        expected_iss = 'eg'
        expected_key_id = 'eg/ex'
        jwt_auth_signer = atlassian_jwt_auth.create_signer(
            expected_iss,
            expected_key_id,
            self._private_key_pem)
        jwt_auth_signer._now = lambda: expected_now
        for additional_claims in [{}, {'extra': 'thing'}]:
            expected_claims = {
                'iss': expected_iss,
                'exp': expected_now + datetime.timedelta(hours=1),
                'iat': expected_now,
                'aud': expected_audience,
                'nbf': expected_now,
                'sub': expected_iss,
            }
            expected_claims.update(additional_claims)
            claims = jwt_auth_signer._generate_claims(
                expected_audience,
                additional_claims=additional_claims)
            self.assertIsNotNone(claims['jti'])
            del claims['jti']
            self.assertEqual(claims, expected_claims)

    def test_jti_changes(self):
        """ tests that the jti of a claim changes. """
        expected_now = datetime.datetime(year=2001, day=1, month=1)
        aud = 'aud'
        jwt_auth_signer = utils.get_example_jwt_auth_signer(
            algorithm=self.algorithm, private_key_pem=self._private_key_pem)
        jwt_auth_signer._now = lambda: expected_now
        first = jwt_auth_signer._generate_claims(aud)['jti']
        second = jwt_auth_signer._generate_claims(aud)['jti']
        self.assertNotEqual(first, second)
        self.assertTrue(str(expected_now.strftime('%s')) in first)
        self.assertTrue(str(expected_now.strftime('%s')) in second)

    @mock.patch('jwt.encode')
    def test_generate_jwt(self, m_jwt_encode):
        """ tests that generate_jwt works as expected. """
        expected_aud = 'aud_x'
        expected_claims = {'eg': 'ex'}
        expected_key_id = 'key_id'
        expected_issuer = 'a_issuer'
        jwt_auth_signer = atlassian_jwt_auth.create_signer(
            expected_issuer,
            expected_key_id,
            private_key_pem=self._private_key_pem,
            algorithm=self.algorithm,
        )
        jwt_auth_signer._generate_claims = lambda aud: expected_claims
        jwt_auth_signer.generate_jwt(expected_aud)
        m_jwt_encode.assert_called_with(
            expected_claims,
            key=self._private_key_pem,
            algorithm=self.algorithm,
            headers={'kid': expected_key_id})


class JWTAuthSignerRS256Test(
        BaseJWTAuthSignerTest,
        utils.RS256KeyTestMixin,
        unittest.TestCase):
    pass


class JWTAuthSignerES256Test(
        BaseJWTAuthSignerTest,
        utils.ES256KeyTestMixin,
        unittest.TestCase):
    pass
