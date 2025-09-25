import datetime
import unittest
from unittest import mock
from unittest.mock import Mock

from cryptography.hazmat.primitives import serialization

import atlassian_jwt_auth
from atlassian_jwt_auth.tests import utils


class BaseJWTAuthSignerTest(object):

    """ tests for the JWTAuthSigner class. """

    def setUp(self) -> None:
        self._private_key_pem = self.get_new_private_key_in_pem_format()  # type: ignore[attr-defined]

    def test__generate_claims(self) -> None:
        """ tests that _generate_claims works as expected. """
        expected_now = datetime.datetime(year=2001, day=1, month=1)
        expected_audience = 'example_aud'
        expected_iss = 'eg'
        expected_key_id = 'eg/ex'
        jwt_auth_signer = atlassian_jwt_auth.create_signer(
            expected_iss,
            expected_key_id,
            self._private_key_pem)
        jwt_auth_signer._now = lambda: expected_now  # type: ignore[method-assign]
        for additional_claims in [{}, {'extra': 'thing'}]:
            expected_claims = {
                'iss': expected_iss,
                'exp': expected_now + datetime.timedelta(minutes=1),
                'iat': expected_now,
                'aud': expected_audience,
                'nbf': expected_now,
                'sub': expected_iss,
            }
            expected_claims.update(additional_claims)
            claims = jwt_auth_signer._generate_claims(
                expected_audience,
                additional_claims=additional_claims)
            self.assertIsNotNone(claims['jti'])  # type: ignore[attr-defined]
            del claims['jti']
            self.assertEqual(claims, expected_claims)  # type: ignore[attr-defined]

    def test_jti_changes(self) -> None:
        """ tests that the jti of a claim changes. """
        expected_now = datetime.datetime(year=2001, day=1, month=1)
        aud = 'aud'
        jwt_auth_signer = utils.get_example_jwt_auth_signer(
            algorithm=self.algorithm, private_key_pem=self._private_key_pem)  # type: ignore[attr-defined]
        jwt_auth_signer._now = lambda: expected_now  # type: ignore[method-assign]
        first = jwt_auth_signer._generate_claims(aud)['jti']
        second = jwt_auth_signer._generate_claims(aud)['jti']
        self.assertNotEqual(first, second)  # type: ignore[attr-defined]
        self.assertTrue(str(expected_now.strftime('%s')) in first)  # type: ignore[attr-defined]
        self.assertTrue(str(expected_now.strftime('%s')) in second)  # type: ignore[attr-defined]

    @mock.patch('jwt.encode')
    def test_generate_jwt(self, m_jwt_encode: Mock) -> None:
        """ tests that generate_jwt works as expected. """
        expected_aud = 'aud_x'
        expected_claims = {'eg': 'ex'}
        expected_key_id = 'key_id'
        expected_issuer = 'a_issuer'
        jwt_auth_signer = atlassian_jwt_auth.create_signer(
            expected_issuer,
            expected_key_id,
            private_key_pem=self._private_key_pem,
            algorithm=self.algorithm,  # type: ignore[attr-defined]
        )
        jwt_auth_signer._generate_claims = lambda aud: expected_claims  # type: ignore[assignment, method-assign, misc]
        jwt_auth_signer.generate_jwt(expected_aud)
        m_jwt_encode.assert_called_with(
            expected_claims,
            key=mock.ANY,
            algorithm=self.algorithm,  # type: ignore[attr-defined]
            headers={'kid': expected_key_id})
        for name, args, kwargs in m_jwt_encode.mock_calls:
            if not kwargs:
                self.assertEqual(args[0], 'utf-8')  # type: ignore[attr-defined]
                continue
            call_private_key = kwargs['key'].private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            self.assertEqual(call_private_key, self._private_key_pem)  # type: ignore[attr-defined]


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
