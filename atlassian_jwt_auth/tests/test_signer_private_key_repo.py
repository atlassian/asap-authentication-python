import os
import unittest

import atlassian_jwt_auth
from atlassian_jwt_auth import key


class JWTAuthSignerWithFilePrivateKeyRetrieverTest(unittest.TestCase):

    """ tests for the JWTAuthSigner using the FilePrivateKeyRetriever. """

    def create_signer_for_issuer(self, issuer):
        this_dir = os.path.dirname(__file__)
        private_key_repository_path = os.path.join(this_dir, 'jwtprivatekeys')
        return \
            atlassian_jwt_auth.create_signer_from_file_private_key_repository(
                issuer, private_key_repository_path)

    def test_succeeds_if_issuer_has_one_valid_key(self):
        signer = self.create_signer_for_issuer('valid-issuer')
        token = signer.generate_jwt('audience')
        self.assertIsNotNone(token)

    def test_picks_last_valid_key_id(self):
        signer = self.create_signer_for_issuer('issuer-with-many-keys')
        token = signer.generate_jwt('audience')
        key_identifier = key._get_key_id_from_jwt_header(token)

        expected_key_id = 'issuer-with-many-keys/key3.pem'
        self.assertEqual(key_identifier.key_id, expected_key_id)

    def test_fails_if_issuer_has_no_valid_keys(self):
        signer = self.create_signer_for_issuer('invalid-issuer')
        with self.assertRaisesRegexp(IOError, 'Issuer has no valid keys'):
            signer.generate_jwt('audience')

    def test_fails_if_issuer_does_not_exist(self):
        signer = self.create_signer_for_issuer('this-does-not-exist')
        with self.assertRaisesRegexp(OSError, 'No such file or directory'):
            signer.generate_jwt('audience')
