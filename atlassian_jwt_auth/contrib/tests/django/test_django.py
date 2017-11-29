import os

import django
from django.test.testcases import SimpleTestCase
from django.test.utils import override_settings, modify_settings
try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse

from atlassian_jwt_auth import create_signer
from atlassian_jwt_auth.contrib.tests.utils import get_static_retriever_class
from atlassian_jwt_auth.tests import utils
from atlassian_jwt_auth.tests.utils import RS256KeyTestMixin


def create_token(issuer, audience, key_id, private_key):
    signer = create_signer(issuer, key_id, private_key)
    return signer.generate_jwt(audience)


class DjangoAsapMixin(object):

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault(
            'DJANGO_SETTINGS_MODULE',
            'atlassian_jwt_auth.contrib.tests.django.settings')

        django.setup()
        super(DjangoAsapMixin, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(DjangoAsapMixin, cls).tearDownClass()
        del os.environ['DJANGO_SETTINGS_MODULE']

    def setUp(self):
        super(DjangoAsapMixin, self).setUp()
        self._private_key_pem = self.get_new_private_key_in_pem_format()
        self._public_key_pem = utils.get_public_key_pem_for_private_key_pem(
            self._private_key_pem
        )

        self.retriever = get_static_retriever_class({
            'client-app/key01': self._public_key_pem
        })

        self.test_settings = {
            'ASAP_KEY_RETRIEVER_CLASS': self.retriever
        }


@modify_settings(MIDDLEWARE={
    'prepend': 'atlassian_jwt_auth.contrib.django.middleware.ASAPMiddleware',
})
class TestAsapMiddleware(DjangoAsapMixin, RS256KeyTestMixin, SimpleTestCase):

    def check_response(self,
                       view_name,
                       response_content='',
                       status_code=200,
                       issuer='client-app',
                       audience='server-app',
                       key_id='client-app/key01',
                       private_key=None,
                       token=None,
                       authorization=None,
                       retriever_key=None):
        if authorization is None:
            if token is None:
                if private_key is None:
                    private_key = self._private_key_pem
                token = create_token(issuer=issuer, audience=audience,
                                     key_id=key_id, private_key=private_key)
            authorization = b'Bearer ' + token

        test_settings = self.test_settings.copy()
        if retriever_key is not None:
            retriever = get_static_retriever_class({
                retriever_key: self._public_key_pem
            })
            test_settings['ASAP_KEY_RETRIEVER_CLASS'] = retriever

        with override_settings(**test_settings):
            response = self.client.get(reverse(view_name),
                                       HTTP_AUTHORIZATION=authorization)

        self.assertContains(response, response_content,
                            status_code=status_code)

    def test_request_with_valid_token_is_allowed(self):
        self.check_response('needed', 'one', 200)

    def test_request_with_string_headers_is_allowed(self):
        token = create_token(
            issuer='client-app', audience='server-app',
            key_id='client-app/key01', private_key=self._private_key_pem
        )
        str_auth = 'Bearer ' + token.decode(encoding='iso-8859-1')
        self.check_response('needed', 'one', 200, authorization=str_auth)

    def test_request_with_invalid_audience_is_rejected(self):
        self.check_response('needed', 'Unauthorized', 401,
                            audience='invalid')

    def test_request_with_invalid_token_is_rejected(self):
        self.check_response('needed', 'Unauthorized', 401,
                            authorization='Bearer invalid')

    def test_request_without_token_is_rejected(self):
        with override_settings(**self.test_settings):
            response = self.client.get(reverse('needed'))

        self.assertContains(response, 'Unauthorized',
                            status_code=401)

    def test_request_with_invalid_issuer_is_rejected(self):
        self.check_response('needed', 'Forbidden', 403,
                            issuer='something-invalid',
                            key_id='something-invalid/key01',
                            retriever_key='something-invalid/key01')

    def test_request_non_whitelisted_decorated_issuer_is_rejected(self):
        self.check_response('needed', 'Forbidden', 403,
                            issuer='unexpected',
                            key_id='unexpected/key01',
                            retriever_key='unexpected/key01')

    def test_request_non_decorated_issuer_is_rejected(self):
        self.check_response('restricted_issuer', 'Forbidden', 403)

    def test_request_decorated_issuer_is_allowed(self):
        self.check_response('restricted_issuer', 'three',
                            issuer='whitelist',
                            key_id='whitelist/key01',
                            retriever_key='whitelist/key01')

    # TODO: modify JWTAuthSigner to allow non-issuer subjects and update the
    # decorated subject test cases
    def test_request_non_decorated_subject_is_rejected(self):
        self.check_response('restricted_subject', 'Forbidden', 403,
                            issuer='whitelist',
                            key_id='whitelist/key01',
                            retriever_key='whitelist/key01')

    def test_request_decorated_subject_is_allowed(self):
        self.check_response('restricted_subject', 'four')

    def test_request_using_settings_only_is_allowed(self):
        self.check_response('unneeded', 'two')


class TestAsapDecorator(DjangoAsapMixin, RS256KeyTestMixin, SimpleTestCase):

    def get(self, url, token, settings=None):
        if settings is None:
            settings = self.test_settings
        with override_settings(**settings):
            return self.client.get(url, HTTP_AUTHORIZATION=b'Bearer ' + token)

    def test_request_with_valid_token_is_allowed(self):
        token = create_token(
            issuer='client-app', audience='server-app',
            key_id='client-app/key01', private_key=self._private_key_pem
        )
        with override_settings(**self.test_settings):
            response = self.client.get(reverse('expected'),
                                       HTTP_AUTHORIZATION=b'Bearer ' + token)

        self.assertContains(response, 'Greatest Success!', status_code=200)

    def test_request_with_string_headers_is_allowed(self):
        token = create_token(
            issuer='client-app', audience='server-app',
            key_id='client-app/key01', private_key=self._private_key_pem
        )
        str_token = token.decode(encoding='iso-8859-1')
        with override_settings(**self.test_settings):
            response = self.client.get(reverse('expected'),
                                       HTTP_AUTHORIZATION='Bearer ' +
                                                          str_token)

        self.assertContains(response, 'Greatest Success!', status_code=200)

    def test_request_with_invalid_audience_is_rejected(self):
        token = create_token(
            issuer='client-app', audience='something-invalid',
            key_id='client-app/key01', private_key=self._private_key_pem
        )
        with override_settings(**self.test_settings):
            response = self.client.get(reverse('expected'),
                                       HTTP_AUTHORIZATION=b'Bearer ' + token)

        self.assertContains(response, 'Unauthorized: Invalid token',
                            status_code=401)

    def test_request_with_invalid_token_is_rejected(self):
        with override_settings(**self.test_settings):
            response = self.client.get(
                reverse('expected'),
                HTTP_AUTHORIZATION=b'Bearer notavalidtoken')

        self.assertContains(response, 'Unauthorized: Invalid token',
                            status_code=401)

    def test_request_without_token_is_rejected(self):
        with override_settings(**self.test_settings):
            response = self.client.get(reverse('expected'))

        self.assertContains(response, 'Unauthorized',
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
            response = self.client.get(reverse('expected'),
                                       HTTP_AUTHORIZATION=b'Bearer ' + token)

        self.assertContains(response, 'Forbidden: Invalid token issuer',
                            status_code=403)

    def test_request_non_whitelisted_decorated_issuer_is_rejected(self):
        retriever = get_static_retriever_class({
            'unexpected/key01': self._public_key_pem
        })
        token = create_token(
            issuer='unexpected', audience='server-app',
            key_id='unexpected/key01', private_key=self._private_key_pem
        )

        with override_settings(ASAP_KEY_RETRIEVER_CLASS=retriever):
            response = self.client.get(reverse('unexpected'),
                                       HTTP_AUTHORIZATION=b'Bearer ' + token)

        self.assertContains(response, 'Forbidden: Invalid token issuer',
                            status_code=403)

    def test_request_non_decorated_issuer_is_rejected(self):
        token = create_token(
            issuer='client-app', audience='server-app',
            key_id='client-app/key01', private_key=self._private_key_pem
        )
        with override_settings(**self.test_settings):
            response = self.client.get(reverse('decorated'),
                                       HTTP_AUTHORIZATION=b'Bearer ' + token)

        self.assertContains(response, 'Forbidden: Invalid token issuer',
                            status_code=403)

    def test_request_decorated_issuer_is_allowed(self):
        retriever = get_static_retriever_class({
            'whitelist/key01': self._public_key_pem
        })
        token = create_token(
            issuer='whitelist', audience='server-app',
            key_id='whitelist/key01', private_key=self._private_key_pem
        )
        with override_settings(ASAP_KEY_RETRIEVER_CLASS=retriever):
            response = self.client.get(reverse('decorated'),
                                       HTTP_AUTHORIZATION=b'Bearer ' + token)

        self.assertContains(response, 'Only the right issuer is allowed.')

    def test_request_using_settings_only_is_allowed(self):
        token = create_token(
            issuer='client-app', audience='server-app',
            key_id='client-app/key01', private_key=self._private_key_pem
        )
        with override_settings(**self.test_settings):
            response = self.client.get(reverse('settings'),
                                       HTTP_AUTHORIZATION=b'Bearer ' + token)

        self.assertContains(response, 'Any settings issuer is allowed.')
