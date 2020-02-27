import unittest

from atlassian_jwt_auth.contrib.tests.utils import get_static_retriever_class
from atlassian_jwt_auth.frameworks.wsgi.middleware import ASAPMiddleware
from atlassian_jwt_auth.tests import utils
from atlassian_jwt_auth.tests.utils import (
    create_token,
)


def app(environ, start_response):
    start_response('200 OK', [], None)
    return "OK"


class WsgiTests(utils.RS256KeyTestMixin, unittest.TestCase):
    """ tests for the atlassian_jwt_auth.contrib.tests.flask """

    def setUp(self):
        self._private_key_pem = self.get_new_private_key_in_pem_format()
        self._public_key_pem = utils.get_public_key_pem_for_private_key_pem(
            self._private_key_pem
        )

        retriever = get_static_retriever_class({
            'client-app/key01': self._public_key_pem
        })
        self.config = {
            'ASAP_VALID_AUDIENCE': 'server-app',
            'ASAP_VALID_ISSUERS': ('client-app',),
            'ASAP_KEY_RETRIEVER_CLASS': retriever
        }

    def get_app_with_middleware(self, config):
        return ASAPMiddleware(app, config)

    def send_request(self, url='/', config=None, token=None, application=None):
        """ returns the response of sending a request containing the given
            token sent in the Authorization header.
        """

        resp_info = {}

        def start_response(status, response_headers, exc_info=None):
            resp_info['status'] = status
            resp_info['headers'] = response_headers

        environ = {}
        if token:
            environ['HTTP_AUTHORIZATION'] = b'Bearer ' + token
        if application is None:
            application = self.get_app_with_middleware(config or self.config)
        return application(environ, start_response), resp_info, environ

    def test_request_with_valid_token_is_allowed(self):
        token = create_token(
            'client-app', 'server-app',
            'client-app/key01', self._private_key_pem
        )
        body, resp_info, environ = self.send_request(token=token)
        self.assertEqual(resp_info['status'], '200 OK')
        self.assertIn('ATL_ASAP_CLAIMS', environ)

    def test_request_with_duplicate_jti_is_rejected_as_per_setting(self):
        self.config['ASAP_CHECK_JTI_UNIQUENESS'] = True
        token = create_token(
            'client-app', 'server-app',
            'client-app/key01', self._private_key_pem
        )
        application = self.get_app_with_middleware(self.config)
        body, resp_info, environ = self.send_request(
            token=token, application=application)
        self.assertEqual(resp_info['status'], '200 OK')
        body, resp_info, environ = self.send_request(
            token=token, application=application)
        self.assertEqual(resp_info['status'], '401 Unauthorized')

    def _assert_request_with_duplicate_jti_is_accepted(self):
        token = create_token(
            'client-app', 'server-app',
            'client-app/key01', self._private_key_pem
        )
        application = self.get_app_with_middleware(self.config)
        body, resp_info, environ = self.send_request(
            token=token, application=application)
        self.assertEqual(resp_info['status'], '200 OK')
        body, resp_info, environ = self.send_request(
            token=token, application=application)
        self.assertEqual(resp_info['status'], '200 OK')

    def test_request_with_duplicate_jti_is_accepted(self):
        self._assert_request_with_duplicate_jti_is_accepted()

    def test_request_with_duplicate_jti_is_accepted_as_per_setting(self):
        self.config['ASAP_CHECK_JTI_UNIQUENESS'] = False
        self._assert_request_with_duplicate_jti_is_accepted()

    def test_request_with_invalid_audience_is_rejected(self):
        token = create_token(
            'client-app', 'invalid-audience',
            'client-app/key01', self._private_key_pem
        )
        body, resp_info, environ = self.send_request(token=token)
        self.assertEqual(resp_info['status'], '401 Unauthorized')
        self.assertNotIn('ATL_ASAP_CLAIMS', environ)

    def test_request_with_invalid_token_is_rejected(self):
        body, resp_info, environ = self.send_request(token=b'notavalidtoken')
        self.assertEqual(resp_info['status'], '401 Unauthorized')
        self.assertNotIn('ATL_ASAP_CLAIMS', environ)

    def test_request_subject_and_issue_not_matching(self):
        token = create_token(
            'client-app', 'server-app',
            'client-app/key01', self._private_key_pem,
            subject='different'
        )
        body, resp_info, environ = self.send_request(token=token)
        self.assertEqual(resp_info['status'], '401 Unauthorized')
        self.assertNotIn('ATL_ASAP_CLAIMS', environ)

    def test_request_subject_does_not_need_to_match_issuer_from_settings(self):
        self.config['ASAP_SUBJECT_SHOULD_MATCH_ISSUER'] = False
        token = create_token(
            'client-app', 'server-app',
            'client-app/key01', self._private_key_pem,
            subject='different'
        )
        body, resp_info, environ = self.send_request(token=token)
        self.assertEqual(resp_info['status'], '200 OK')
        self.assertIn('ATL_ASAP_CLAIMS', environ)
