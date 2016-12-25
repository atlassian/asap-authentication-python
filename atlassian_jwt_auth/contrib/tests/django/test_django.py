import django
import os

from django.test.testcases import SimpleTestCase
from django.test.utils import override_settings

from atlassian_jwt_auth import create_signer
from atlassian_jwt_auth.contrib.tests.utils import get_static_retriever_class
from atlassian_jwt_auth.tests import utils


os.environ.setdefault('DJANGO_SETTINGS_MODULE',
                      'atlassian_jwt_auth.contrib.tests.django.settings')

django.setup()


def create_token(issuer, audience, key_id, private_key):
    signer = create_signer(issuer, key_id, private_key)

    return signer.generate_jwt(audience)


class TestAsapDecorator(SimpleTestCase):
    _private_key_pem = utils.get_new_rsa_private_key_in_pem_format()
    _public_key_pem = utils.get_public_key_pem_for_private_key_pem(
        _private_key_pem
    )

    retriever = get_static_retriever_class({
        'client-app/key01': _public_key_pem
    })

    test_settings = {
        'ASAP_KEY_RETRIEVER_CLASS': retriever
    }

    @override_settings(**test_settings)
    def test_request_with_valid_token_is_allowed(self):
        token = create_token(
            issuer='client-app', audience='server-app',
            key_id='client-app/key01', private_key=self._private_key_pem
        )
        response = self.client.get('/asap/test1',
                                   AUTHORIZATION=b'Bearer ' + token)

        self.assertContains(response, 'Greatest Success!', status_code=200)

    @override_settings(**test_settings)
    def test_request_with_invalid_audience_is_rejected(self):
        token = create_token(
            issuer='client-app', audience='something-invalid',
            key_id='client-app/key01', private_key=self._private_key_pem
        )
        response = self.client.get('/asap/test1',
                                   AUTHORIZATION=b'Bearer ' + token)

        self.assertContains(response, 'Unauthorized: Invalid token',
                            status_code=401)

    @override_settings(**test_settings)
    def test_request_with_invalid_token_is_rejected(self):
        response = self.client.get('/asap/test1',
                                   AUTHORIZATION=b'Bearer notavalidtoken')

        print(response)
        self.assertContains(response, 'Unauthorized: Invalid token',
                            status_code=401)

    def test_request_with_invalid_issuer_is_rejected(self):
        retriever = get_static_retriever_class({
            'something-invalid/key01': self._public_key_pem
        })

        token = create_token(
            issuer='something-invalid', audience='server-app',
            key_id='something-invalid/key01', private_key=self._private_key_pem
        )

        with override_settings(ASAP_KEY_RETRIEVER_CLASS=retriever):
            response = self.client.get('/asap/test1',
                                       AUTHORIZATION=b'Bearer ' + token)

            self.assertContains(response, 'Unauthorized: Invalid token issuer',
                                status_code=401)
