import base64
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import serialization

from atlassian_jwt_auth.signer import JWTAuthSigner
from atlassian_jwt_auth.tests import utils
from atlassian_jwt_auth.key import DataUriPrivateKeyRetriever


def convert_key_pem_format_to_der_format(private_key_pem):
    private_key = load_pem_private_key(private_key_pem,
                                       password=None,
                                       backend=default_backend())
    return private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


class BaseDataUriPrivateKeyRetrieverTest(object):
    """ tests for the DataUriPrivateKeyRetriever class. """

    def setUp(self):
        self._private_key_pem = self.get_new_private_key_in_pem_format()
        self._public_key_pem = utils.get_public_key_pem_for_private_key_pem(
            self._private_key_pem)
        self._private_key_der = convert_key_pem_format_to_der_format(
            self._private_key_pem)

    def get_example_data_uri(self, private_key_der):
        return ('data:application/pkcs8;kid=example%2Feg;base64,' +
                base64.b64encode(private_key_der).decode('utf-8'))

    def test_load_data_uri(self):
        """ tests that a valid data uri is correctly loaded. """
        expected_kid = 'example/eg'
        data_uri = self.get_example_data_uri(self._private_key_der)
        provider = DataUriPrivateKeyRetriever(data_uri)
        kid, private_key_pem = provider.load('example')
        self.assertEqual(kid.key_id, expected_kid)
        self.assertEqual(private_key_pem,
                         self._private_key_pem.decode('utf-8'))

    def test_load_data_uri_can_be_used_with_a_signer(self):
        """ tests that the data uri private key retriever can be used with a
            signer to generate a jwt.
        """
        data_uri = self.get_example_data_uri(self._private_key_der)
        provider = DataUriPrivateKeyRetriever(data_uri)
        jwt_auth_signer = JWTAuthSigner(
            'issuer', provider, algorithm=self.algorithm)
        jwt_auth_signer.generate_jwt('aud')


class DataUriPrivateKeyRetrieverRS256Test(BaseDataUriPrivateKeyRetrieverTest,
                                          utils.RS256KeyTestMixin,
                                          unittest.TestCase):
    pass


class DataUriPrivateKeyRetrieverES256Test(BaseDataUriPrivateKeyRetrieverTest,
                                          utils.ES256KeyTestMixin,
                                          unittest.TestCase):
    pass
