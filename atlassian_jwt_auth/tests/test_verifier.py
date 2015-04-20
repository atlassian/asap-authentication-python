import datetime
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
        self._example_aud = 'aud_x'
        self._example_issuer = 'egissuer'
        self._example_key_id = '%s/a' % self._example_issuer
        self._jwt_auth_signer = JWTAuthSigner(
            self._example_issuer,
            self._example_key_id,
            self._private_key_pem.decode(),
        )

    def _setup_mock_public_key_retriever(self, pub_key_pem):
        m_public_key_ret = mock.Mock()
        m_public_key_ret.retrieve.return_value = pub_key_pem.decode()
        return m_public_key_ret

    def _setup_jwt_auth_verifier(self, pub_key_pem):
        m_public_key_ret = self._setup_mock_public_key_retriever(pub_key_pem)
        return JWTAuthVerifier(m_public_key_ret)

    def test_verify_claims_with_valid_jwt(self):
        """ test that verify_claims verifies a valid jwt. """
        verifier = self._setup_jwt_auth_verifier(self._public_key_pem)
        signed_claims = self._jwt_auth_signer.get_signed_claims(
            self._example_aud)
        v_claims = verifier.verify_claims(signed_claims, self._example_aud)
        self.assertIsNotNone(v_claims)
        self.assertEqual(v_claims['aud'], self._example_aud)
        self.assertEqual(v_claims['iss'], self._example_issuer)

    def test_verify_claims_with_key_identifier_not_starting_with_issuer(self):
        """ tests that verify_claims rejects a jwt if the key identifier does
            not start with the claimed issuer.
        """
        verifier = self._setup_jwt_auth_verifier(self._public_key_pem)
        signer = JWTAuthSigner(
            'issuer', 'issuerx', self._private_key_pem.decode())
        signed_claims = signer.get_signed_claims(self._example_aud)
        with self.assertRaisesRegex(ValueError, 'Issuer does not own'):
            verifier.verify_claims(signed_claims, self._example_aud)

    @mock.patch('atlassian_jwt_auth.verifier.jwt.decode')
    def test_verify_claims_with_non_matching_sub_and_iss(self, m_j_decode):
        """ tests that verify_claims rejects a jwt if the claims
            contains a subject which does not match the issuer.
        """
        expected_msg = 'Issuer does not match the subject'
        m_j_decode.return_value = {
            'iss': self._example_issuer,
            'sub': self._example_issuer[::-1]
        }
        a_jwt = self._jwt_auth_signer.get_signed_claims(self._example_aud)
        verifier = self._setup_jwt_auth_verifier(self._public_key_pem)
        with self.assertRaisesRegex(ValueError, expected_msg):
            verifier.verify_claims(a_jwt, self._example_aud)

    @mock.patch('atlassian_jwt_auth.verifier.jwt.decode')
    def test_verify_claims_with_jwt_lasting_gt_max_time(self, m_j_decode):
        """ tests that verify_claims rejects a jwt if the claims
            period of validity is greater than the allowed maximum.
        """
        expected_msg = 'exceeds the maximum'
        claims = self._jwt_auth_signer._get_claims(self._example_aud)
        claims['iat'] = claims['exp'] - datetime.timedelta(minutes=61)
        for key in ['iat', 'exp']:
            claims[key] = claims[key].timestamp()
        m_j_decode.return_value = claims
        a_jwt = self._jwt_auth_signer.get_signed_claims(self._example_aud)
        verifier = self._setup_jwt_auth_verifier(self._public_key_pem)
        with self.assertRaisesRegex(ValueError, expected_msg):
            verifier.verify_claims(a_jwt, self._example_aud)

    def test_verify_claims_with_jwt_with_already_seen_jti(self):
        """ tests that verify_claims rejects a jwt if the jti
            has already been seen.
        """
        verifier = self._setup_jwt_auth_verifier(self._public_key_pem)
        signed_claims = self._jwt_auth_signer.get_signed_claims(
            self._example_aud)
        self.assertIsNotNone(verifier.verify_claims(
            signed_claims,
            self._example_aud))
        with self.assertRaisesRegex(ValueError, 'has already been used'):
            verifier.verify_claims(signed_claims, self._example_aud)
