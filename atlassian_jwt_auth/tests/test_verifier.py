import unittest

import mock

from ..signer import JWTAuthSigner
from ..verifier import JWTAuthVerifier
from .utils import (
    get_new_rsa_private_key_in_pem_format,
    get_public_key_pem_for_private_key_pem,
)


class TestJWTAuthVerifier(unittest.TestCase):

    """ tests for the JWTAuthVerifier class. """

    def setUp(self):
        self._private_key_pem = get_new_rsa_private_key_in_pem_format()
        self._public_key_pem = get_public_key_pem_for_private_key_pem(
            self._private_key_pem)

    def _setup_mock_public_key_retriever(self, pub_key_pem):
        m_public_key_ret = mock.Mock()
        m_public_key_ret.retrieve.return_value = pub_key_pem.decode()
        return m_public_key_ret

    def test_verify_claims_with_valid_jwt(self):
        """ test that verify_claims verifies a valid jwt. """
        expected_audience = 'aud_x'
        expected_issuer = 'issuer'
        expected_key_id = '%s/a' % expected_issuer
        m_public_key_ret = self._setup_mock_public_key_retriever(
            self._public_key_pem)
        verifier = JWTAuthVerifier(m_public_key_ret)
        signer = JWTAuthSigner(
            expected_issuer,
            expected_key_id,
            self._private_key_pem.decode())
        signed_claims = signer.get_signed_claims(expected_audience)
        v_claims = verifier.verify_claims(signed_claims, expected_audience)
        self.assertIsNotNone(v_claims)
        self.assertEqual(v_claims['aud'], expected_audience)
        self.assertEqual(v_claims['iss'], expected_issuer)
