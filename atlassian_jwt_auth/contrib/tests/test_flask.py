import unittest

from flask import Flask
from mock import patch

import atlassian_jwt_auth
from atlassian_jwt_auth.tests import utils
from atlassian_jwt_auth.contrib.flask_app import requires_asap
from atlassian_jwt_auth.contrib.tests.utils import static_verifier


def get_app():
    app = Flask(__name__)
    app.config.asap = {
        'VALID_AUDIENCE': 'server-app',
        'VALID_ISSUERS': ['client-app']
    }

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

        self.verifier = static_verifier(
            {'client-app/key01': self._public_key_pem}
        )

    @patch('atlassian_jwt_auth.contrib.flask_app.decorators._get_verifier')
    def test_request_with_valid_token_is_allowed(self, get_verifier):
        app = get_app()
        client = app.test_client()

        get_verifier.side_effect = lambda: self.verifier
        token = create_token(
            'client-app', 'server-app',
            'client-app/key01', self._private_key_pem
        )
        response = client.get('/', headers={
            'Authorization': b'Bearer ' + token
        })

        self.assertEqual(response.status_code, 200)

    @patch('atlassian_jwt_auth.contrib.flask_app.decorators._get_verifier')
    def test_request_with_invalid_audience_is_rejected(self, get_verifier):
        app = get_app()
        client = app.test_client()

        get_verifier.side_effect = lambda: self.verifier
        token = create_token(
            'client-app', 'invalid-audience',
            'client-app/key01', self._private_key_pem
        )
        response = client.get('/', headers={
            'Authorization': b'Bearer ' + token
        })

        self.assertEqual(response.status_code, 401)

    @patch('atlassian_jwt_auth.contrib.flask_app.decorators._get_verifier')
    def test_request_with_invalid_token_is_rejected(self, get_verifier):
        app = get_app()
        client = app.test_client()

        get_verifier.side_effect = lambda: self.verifier
        response = client.get('/', headers={
            'Authorization': b'Bearer notavalidtoken'
        })

        self.assertEqual(response.status_code, 401)

    @patch('atlassian_jwt_auth.contrib.flask_app.decorators._get_verifier')
    def test_request_with_invalid_issuer_is_rejected(self, get_verifier):
        app = get_app()
        client = app.test_client()

        # Try with a different audience with a valid signature
        self.verifier = static_verifier(
            {'another-client/key01': self._public_key_pem}
        )

        get_verifier.side_effect = lambda: self.verifier
        token = create_token(
            'another-client', 'server-app',
            'another-client/key01', self._private_key_pem
        )
        response = client.get('/', headers={
            'Authorization': b'Bearer ' + token
        })

        self.assertEqual(response.status_code, 401)
