import os
import shutil
import tempfile
import unittest


import atlassian_jwt_auth
from atlassian_jwt_auth import key
from atlassian_jwt_auth.tests import utils


class BaseJWTAuthSignerWithFilePrivateKeyRetrieverTest(object):

    """ tests for the JWTAuthSigner using the FilePrivateKeyRetriever. """

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix='atlassian-jwt-p-tests')
        self.key_dir = os.path.join(self.test_dir, 'jwtprivatekeys')
        for dir in ['invalid-issuer', 'issuer-with-many-keys',
                    'valid-issuer']:
            os.makedirs(os.path.join(self.key_dir, dir))
        self._private_key_pem = self.get_new_private_key_in_pem_format()
        for file_loc in [
            'invalid-issuer/key-tests-pem.new',
            'issuer-with-many-keys/key1.pem.new',
            'issuer-with-many-keys/key2.pem',
            'issuer-with-many-keys/key3.pem',
            'issuer-with-many-keys/key4.pem.new',
            'valid-issuer/key-for-tests.pem'
        ]:
            file_location = os.path.join(self.key_dir, file_loc)
            with open(file_location, 'wb') as f:
                f.write(self._private_key_pem)

    def tearDown(self):
        if self.test_dir:
            shutil.rmtree(self.test_dir)

    def create_signer_for_issuer(self, issuer):
        return \
            atlassian_jwt_auth.create_signer_from_file_private_key_repository(
                issuer, self.key_dir, algorithm=self.algorithm)

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
        with self.assertRaisesRegex(IOError, 'Issuer has no valid keys'):
            signer.generate_jwt('audience')

    def test_fails_if_issuer_does_not_exist(self):
        signer = self.create_signer_for_issuer('this-does-not-exist')
        with self.assertRaisesRegex(OSError, 'No such file or directory'):
            signer.generate_jwt('audience')


class JWTAuthSignerWithFilePrivateKeyRetrieverRS256Test(
        BaseJWTAuthSignerWithFilePrivateKeyRetrieverTest,
        utils.RS256KeyTestMixin,
        unittest.TestCase):
    pass


class JWTAuthSignerWithFilePrivateKeyRetrieverES256Test(
        BaseJWTAuthSignerWithFilePrivateKeyRetrieverTest,
        utils.ES256KeyTestMixin,
        unittest.TestCase):
    pass
