import datetime
import unittest
from unittest import mock

import jwt
import jwt.algorithms
import jwt.exceptions

import atlassian_jwt_auth
import atlassian_jwt_auth.exceptions
import atlassian_jwt_auth.key
import atlassian_jwt_auth.signer
from atlassian_jwt_auth.tests import utils


class NoneAlgorithmJwtAuthSigner(atlassian_jwt_auth.signer.JWTAuthSigner):
    """ A JWTAuthSigner that generates JWTs using the none algorithm
        and supports specifying arbitrary alg jwt header values.
    """

    def generate_jwt(self, audience, **kwargs):
        alg_header = kwargs.get('alg_header', 'none')
        key_identifier, private_key_pem = self.private_key_retriever.load(
            self.issuer)
        return jwt.encode(self._generate_claims(audience, **kwargs),
                          algorithm=None,
                          key=None,
                          headers={'kid': key_identifier.key_id,
                                   'alg': alg_header})


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

    def _setup_jwt_auth_verifier(self, pub_key_pem, **kwargs):
        m_public_key_ret = self._setup_mock_public_key_retriever(pub_key_pem)
        return atlassian_jwt_auth.JWTAuthVerifier(m_public_key_ret, **kwargs)

    def test_verify_jwt_with_valid_jwt(self):
        """ test that verify_jwt verifies a valid jwt. """
        verifier = self._setup_jwt_auth_verifier(self._public_key_pem)
        signed_jwt = self._jwt_auth_signer.generate_jwt(
            self._example_aud)
        v_claims = verifier.verify_jwt(signed_jwt, self._example_aud)
        self.assertIsNotNone(v_claims)
        self.assertEqual(v_claims['aud'], self._example_aud)
        self.assertEqual(v_claims['iss'], self._example_issuer)

    def test_verify_jwt_with_none_algorithm(self):
        """ tests that verify_jwt does not accept jwt that use the none
            algorithm.
        """
        verifier = self._setup_jwt_auth_verifier(self._public_key_pem)
        private_key_ret = atlassian_jwt_auth.key.StaticPrivateKeyRetriever(
            self._example_key_id, self._private_key_pem.decode())
        jwt_signer = NoneAlgorithmJwtAuthSigner(
            issuer=self._example_issuer,
            private_key_retriever=private_key_ret,
        )
        for algorithm in ['none', 'None', 'nOne', 'nonE', 'NONE']:
            if algorithm != 'none':
                jwt.register_algorithm(
                    algorithm, jwt.algorithms.NoneAlgorithm())
            jwt_token = jwt_signer.generate_jwt(
                self._example_aud, alg_header=algorithm)
            if algorithm != 'none':
                jwt.unregister_algorithm(algorithm)
            jwt_headers = jwt.get_unverified_header(jwt_token)
            self.assertEqual(jwt_headers['alg'], algorithm)
            with self.assertRaises(jwt.exceptions.InvalidAlgorithmError):
                verifier.verify_jwt(jwt_token, self._example_aud)

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
        with self.assertRaisesRegex(ValueError, 'Issuer does not own'):
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
        for exception in [
            ValueError,
            atlassian_jwt_auth.exceptions.SubjectDoesNotMatchIssuerException,
        ]:
            with self.assertRaisesRegex(exception, expected_msg):
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
        with self.assertRaisesRegex(ValueError, expected_msg):
            verifier.verify_jwt(a_jwt, self._example_aud)

    def test_verify_jwt_with_jwt_with_already_seen_jti(self):
        """ tests that verify_jwt rejects a jwt if the jti
            has already been seen.
        """
        verifier = self._setup_jwt_auth_verifier(
            self._public_key_pem, check_jti_uniqueness=True)
        a_jwt = self._jwt_auth_signer.generate_jwt(
            self._example_aud)
        self.assertIsNotNone(verifier.verify_jwt(
            a_jwt,
            self._example_aud))
        for exception in [
                ValueError,
                atlassian_jwt_auth.exceptions.JtiUniquenessException]:
            with self.assertRaisesRegex(exception, 'has already been used'):
                verifier.verify_jwt(a_jwt, self._example_aud)

    def assert_jwt_accepted_more_than_once(self, verifier, a_jwt):
        """ asserts that the given jwt is accepted more than once. """
        for i in range(0, 3):
            self.assertIsNotNone(
                verifier.verify_jwt(a_jwt, self._example_aud))

    def test_verify_jwt_with_already_seen_jti_with_uniqueness_disabled(self):
        """ tests that verify_jwt accepts a jwt if the jti
            has already been seen and the verifier has been set
            to not check the uniqueness of jti.
        """
        verifier = self._setup_jwt_auth_verifier(
            self._public_key_pem, check_jti_uniqueness=False)
        a_jwt = self._jwt_auth_signer.generate_jwt(self._example_aud)
        self.assert_jwt_accepted_more_than_once(verifier, a_jwt)

    def test_verify_jwt_with_already_seen_jti_default(self):
        """ tests that verify_jwt by default accepts a jwt if the jti
            has already been seen.
        """
        verifier = self._setup_jwt_auth_verifier(
            self._public_key_pem)
        a_jwt = self._jwt_auth_signer.generate_jwt(self._example_aud)
        self.assert_jwt_accepted_more_than_once(verifier, a_jwt)

    def test_verify_jwt_subject_should_match_issuer(self):
        verifier = self._setup_jwt_auth_verifier(
            self._public_key_pem, subject_should_match_issuer=True)
        a_jwt = self._jwt_auth_signer.generate_jwt(
            self._example_aud,
            additional_claims={'sub': 'not-' + self._example_issuer})
        with self.assertRaisesRegex(ValueError,
                                    'Issuer does not match the subject.'):
            verifier.verify_jwt(a_jwt, self._example_aud)

    def test_verify_jwt_subject_does_not_need_to_match_issuer(self):
        verifier = self._setup_jwt_auth_verifier(
            self._public_key_pem, subject_should_match_issuer=False)
        a_jwt = self._jwt_auth_signer.generate_jwt(
            self._example_aud,
            additional_claims={'sub': 'not-' + self._example_issuer})
        self.assertIsNotNone(verifier.verify_jwt(a_jwt, self._example_aud))

    @mock.patch('atlassian_jwt_auth.verifier.jwt.decode')
    def test_verify_jwt_with_missing_aud_claim(self, m_j_decode):
        """ tests that verify_jwt rejects jwt that do not have an aud
            claim.
        """
        expected_msg = ('Claims validity, the aud claim must be provided and '
                        'cannot be empty.')
        claims = self._jwt_auth_signer._generate_claims(self._example_aud)
        del claims['aud']
        m_j_decode.return_value = claims
        a_jwt = self._jwt_auth_signer.generate_jwt(self._example_aud)
        verifier = self._setup_jwt_auth_verifier(self._public_key_pem)
        with self.assertRaisesRegex(KeyError, expected_msg):
            verifier.verify_jwt(a_jwt, self._example_aud)

    def test_verify_jwt_with_none_aud(self):
        """ tests that verify_jwt rejects jwt that have a None aud claim. """
        verifier = self._setup_jwt_auth_verifier(self._public_key_pem)
        a_jwt = self._jwt_auth_signer.generate_jwt(
            self._example_aud,
            additional_claims={'aud': None})
        exceptions = (jwt.exceptions.InvalidAudienceError,
                      jwt.exceptions.InvalidTokenError)
        with self.assertRaises(exceptions) as cm:
            verifier.verify_jwt(a_jwt, self._example_aud)
        if not isinstance(cm.exception, jwt.exceptions.InvalidAudienceError):
            self.assertIn('aud', str(cm.exception))

    def test_verify_jwt_with_non_matching_aud(self):
        """ tests that verify_jwt rejects a jwt if the aud claim does not
            match the given & expected audience.
        """
        verifier = self._setup_jwt_auth_verifier(self._public_key_pem)
        a_jwt = self._jwt_auth_signer.generate_jwt(
            self._example_aud,
            additional_claims={'aud': self._example_aud + '-different'})
        with self.assertRaises(jwt.exceptions.InvalidAudienceError):
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
