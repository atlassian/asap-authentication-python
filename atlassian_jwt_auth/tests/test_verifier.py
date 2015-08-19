import datetime
import unittest

import mock

import atlassian_jwt_auth
from atlassian_jwt_auth.tests import utils


class BaseJWTAuthVerifierTest(object):

    """ tests for the JWTAuthVerifier class. """

    def setUp(self):
        self._private_key_pem = self.get_new_private_key_in_pem_format()
        self._public_key_pem = utils.get_public_key_pem_for_private_key_pem(
            self._private_key_pem)
        self._example_aud = 'aud_x'
        self._example_issuer = 'egissuer'
        self._example_key_id = '%s/a' % self._example_issuer
        self._jwt_auth_signer = atlassian_jwt_auth.create_signer(
            self._example_issuer,
            self._example_key_id,
            self._private_key_pem.decode(),
            algorithm=self.algorithm
        )

    def _setup_mock_public_key_retriever(self, pub_key_pem):
        m_public_key_ret = mock.Mock()
        m_public_key_ret.retrieve.return_value = pub_key_pem.decode()
        return m_public_key_ret

    def _setup_jwt_auth_verifier(self, pub_key_pem):
        m_public_key_ret = self._setup_mock_public_key_retriever(pub_key_pem)
        return atlassian_jwt_auth.JWTAuthVerifier(m_public_key_ret)

    def test_verify_jwt_with_valid_jwt(self):
        """ test that verify_jwt verifies a valid jwt. """
        verifier = self._setup_jwt_auth_verifier(self._public_key_pem)
        signed_jwt = self._jwt_auth_signer.generate_jwt(
            self._example_aud)
        v_claims = verifier.verify_jwt(signed_jwt, self._example_aud)
        self.assertIsNotNone(v_claims)
        self.assertEqual(v_claims['aud'], self._example_aud)
        self.assertEqual(v_claims['iss'], self._example_issuer)

    def test_verify_jwt_with_key_identifier_not_starting_with_issuer(self):
        """ tests that verify_jwt rejects a jwt if the key identifier does
            not start with the claimed issuer.
        """
        verifier = self._setup_jwt_auth_verifier(self._public_key_pem)
        signer = atlassian_jwt_auth.create_signer(
            'issuer', 'issuerx', self._private_key_pem.decode(),
            algorithm=self.algorithm,
        )
        a_jwt = signer.generate_jwt(self._example_aud)
        with self.assertRaisesRegexp(ValueError, 'Issuer does not own'):
            verifier.verify_jwt(a_jwt, self._example_aud)

    @mock.patch('atlassian_jwt_auth.verifier.jwt.decode')
    def test_verify_jwt_with_non_matching_sub_and_iss(self, m_j_decode):
        """ tests that verify_jwt rejects a jwt if the claims
            contains a subject which does not match the issuer.
        """
        expected_msg = 'Issuer does not match the subject'
        m_j_decode.return_value = {
            'iss': self._example_issuer,
            'sub': self._example_issuer[::-1]
        }
        a_jwt = self._jwt_auth_signer.generate_jwt(self._example_aud)
        verifier = self._setup_jwt_auth_verifier(self._public_key_pem)
        with self.assertRaisesRegexp(ValueError, expected_msg):
            verifier.verify_jwt(a_jwt, self._example_aud)

    @mock.patch('atlassian_jwt_auth.verifier.jwt.decode')
    def test_verify_jwt_with_jwt_lasting_gt_max_time(self, m_j_decode):
        """ tests that verify_jwt rejects a jwt if the claims
            period of validity is greater than the allowed maximum.
        """
        expected_msg = 'exceeds the maximum'
        claims = self._jwt_auth_signer._generate_claims(self._example_aud)
        claims['iat'] = claims['exp'] - datetime.timedelta(minutes=61)
        for key in ['iat', 'exp']:
            claims[key] = claims[key].strftime('%s')
        m_j_decode.return_value = claims
        a_jwt = self._jwt_auth_signer.generate_jwt(self._example_aud)
        verifier = self._setup_jwt_auth_verifier(self._public_key_pem)
        with self.assertRaisesRegexp(ValueError, expected_msg):
            verifier.verify_jwt(a_jwt, self._example_aud)

    def test_verify_jwt_with_jwt_with_already_seen_jti(self):
        """ tests that verify_jwt rejects a jwt if the jti
            has already been seen.
        """
        verifier = self._setup_jwt_auth_verifier(self._public_key_pem)
        a_jwt = self._jwt_auth_signer.generate_jwt(
            self._example_aud)
        self.assertIsNotNone(verifier.verify_jwt(
            a_jwt,
            self._example_aud))
        with self.assertRaisesRegexp(ValueError, 'has already been used'):
            verifier.verify_jwt(a_jwt, self._example_aud)


class JWTAuthVerifierRS256Test(
        BaseJWTAuthVerifierTest,
        utils.RS256KeyTestMixin,
        unittest.TestCase):
    pass


class JWTAuthVerifierES256Test(
        BaseJWTAuthVerifierTest,
        utils.ES256KeyTestMixin,
        unittest.TestCase):
    pass
