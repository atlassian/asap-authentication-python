import unittest

from flask import Flask

import atlassian_jwt_auth
from atlassian_jwt_auth.tests import utils
from atlassian_jwt_auth.contrib.flask_app import requires_asap
from atlassian_jwt_auth.contrib.tests.utils import get_static_retriever_class


def get_app():
    app = Flask(__name__)
    app.config.update({
        'ASAP_VALID_AUDIENCE': 'server-app',
        'ASAP_VALID_ISSUERS': ('client-app',),
        'ASAP_PUBLICKEY_REPOSITORY': None
    })

    @app.route("/")
    @requires_asap
    def view():
        return "OK"

    return app


def create_token(issuer, audience, key_id, private_key):
    signer = atlassian_jwt_auth.create_signer(
        issuer, key_id, private_key
    )
    return signer.generate_jwt(audience)


class FlaskTests(utils.RS256KeyTestMixin, unittest.TestCase):
    """ tests for the atlassian_jwt_auth.contrib.tests.flask """

    def setUp(self):
        self._private_key_pem = self.get_new_private_key_in_pem_format()
        self._public_key_pem = utils.get_public_key_pem_for_private_key_pem(
            self._private_key_pem
        )

        self.app = get_app()
        self.client = self.app.test_client()

        retriever = get_static_retriever_class({
            'client-app/key01': self._public_key_pem
        })
        self.app.config['ASAP_KEY_RETRIEVER_CLASS'] = retriever

    def send_request(self, token):
        """ returns the response of sending a request containing the given
            token sent in the Authorization header.
        """
        return self.client.get('/', headers={
            'Authorization': b'Bearer ' + token
        })

    def test_request_with_valid_token_is_allowed(self):
        token = create_token(
            'client-app', 'server-app',
            'client-app/key01', self._private_key_pem
        )
        self.assertEqual(self.send_request(token).status_code, 200)

    def test_request_with_invalid_audience_is_rejected(self):
        token = create_token(
            'client-app', 'invalid-audience',
            'client-app/key01', self._private_key_pem
        )
        self.assertEqual(self.send_request(token).status_code, 401)

    def test_request_with_invalid_token_is_rejected(self):
        response = self.send_request(b'notavalidtoken')
        self.assertEqual(response.status_code, 401)

    def test_request_with_invalid_issuer_is_rejected(self):
        # Try with a different audience with a valid signature
        self.app.config['ASAP_KEY_RETRIEVER_CLASS'] = (
            get_static_retriever_class({
                'another-client/key01': self._public_key_pem
            })
        )
        token = create_token(
            'another-client', 'server-app',
            'another-client/key01', self._private_key_pem
        )
        self.assertEqual(self.send_request(token).status_code, 403)
