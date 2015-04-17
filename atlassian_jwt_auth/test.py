import datetime
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from .key import KeyIdentifier
from .signer import JWTAuthSigner


class TestKeyModule(unittest.TestCase):

    """ tests for the key module. """

    def test_key_identifier_with_invalid_keys(self):
        """ test that invalid key identifiers are not permitted. """
        keys = ['../aha', '/a', '\c:a', 'lk2j34/#$', 'a../../a', 'a/;a',
                ' ', ' / ', ' /',
                u'dir/some\0thing', 'a/#a', 'a/a?x', 'a/a;',
                ]
        for key in keys:
            with self.assertRaises(ValueError):
                KeyIdentifier(identifier=key)

    def test_key_identifier_with_valid_keys(self):
        """ test that valid keys work as expected. """
        for key in ['oa.oo/a', 'oo.sasdf.asdf/yes', 'oo/o']:
            key_id = KeyIdentifier(identifier=key)
            self.assertEqual(key_id.key_id, key)


class TestJWTAuthSigner(unittest.TestCase):

    """ tests for the JWTAuthSigner class. """

    def setUp(self):
        self.key = get_new_rsa_private_key_in_pem_format()
        self.algorithm = 'RS256'

    def get_example_jwt_auth_signer(self):
        """ returns an example jwt_auth_signer instance. """
        return JWTAuthSigner('issuer', 'key_id', key=self.key)

    def test__get_claims(self):
        """ tests that _get_claims works as expected. """
        expected_now = datetime.datetime(year=2001, day=1, month=1)
        expected_audience = 'example_aud'
        expected_iss = 'eg'
        expected_key_id = 'eg/ex'
        jwt_auth_signer = JWTAuthSigner(
            expected_iss,
            expected_key_id,
            key=self.key)
        jwt_auth_signer._now = lambda: expected_now
        expected_claims = {
            'iss': expected_iss,
            'exp': expected_now + datetime.timedelta(hours=1),
            'iat': expected_now,
            'aud': expected_audience,
            'nbf': expected_now,
            'sub': expected_iss,
        }
        claims = jwt_auth_signer._get_claims(expected_audience)
        self.assertIsNotNone(claims['jti'])
        del claims['jti']
        self.assertEqual(claims, expected_claims)

    def test_jti_changes(self):
        """ tests that the jti of a claim changes. """
        expected_now = datetime.datetime(year=2001, day=1, month=1)
        aud = 'aud'
        jwt_auth_signer = self.get_example_jwt_auth_signer()
        jwt_auth_signer._now = lambda: expected_now
        first = jwt_auth_signer._get_claims(aud)['jti']
        second = jwt_auth_signer._get_claims(aud)['jti']
        self.assertNotEquals(first, second)
        self.assertTrue(str(expected_now.timestamp()) in first)
        self.assertTrue(str(expected_now.timestamp()) in second)


def get_new_rsa_private_key_in_pem_format():
    """ returns a new rsa key in pem format. """
    private_key = rsa.generate_private_key(
        key_size=2048, backend=default_backend(), public_exponent=65537)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
