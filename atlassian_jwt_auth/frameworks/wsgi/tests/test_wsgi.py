import unittest

import atlassian_jwt_auth
from atlassian_jwt_auth.tests import utils
from atlassian_jwt_auth.contrib.tests.utils import get_static_retriever_class
from atlassian_jwt_auth.frameworks.wsgi.middleware import ASAPMiddleware


def app(environ, start_response):
    start_response('200 OK', [], None)
    return "OK"


def create_token(issuer, audience, key_id, private_key):
    signer = atlassian_jwt_auth.create_signer(
        issuer, key_id, private_key
    )
    return signer.generate_jwt(audience)


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

    def send_request(self, url='/', config=None, token=None):
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

        app = self.get_app_with_middleware(config or self.config)
        return app(environ, start_response), resp_info, environ

    def test_request_with_valid_token_is_allowed(self):
        token = create_token(
            'client-app', 'server-app',
            'client-app/key01', self._private_key_pem
        )
        body, resp_info, environ = self.send_request(token=token)
        assert resp_info['status'] == '200 OK'
        assert 'ATL_ASAP_CLAIMS' in environ

    def test_request_with_invalid_audience_is_rejected(self):
        token = create_token(
            'client-app', 'invalid-audience',
            'client-app/key01', self._private_key_pem
        )
        body, resp_info, environ = self.send_request(token=token)
        assert resp_info['status'] == '401 Unauthorized'
        assert 'ATL_ASAP_CLAIMS' not in environ

    def test_request_with_invalid_token_is_rejected(self):
        body, resp_info, environ = self.send_request(token=b'notavalidtoken')
        assert resp_info['status'] == '401 Unauthorized'
        assert 'ATL_ASAP_CLAIMS' not in environ
