import os
from unittest import mock

import aiohttp
from multidict import CIMultiDict

try:
    from unittest import IsolatedAsyncioTestCase as TestCase
    from unittest.mock import AsyncMock as CoroutineMock
    from unittest.mock import Mock
except ImportError:
    from asynctest import CoroutineMock, TestCase, Mock

from atlassian_jwt_auth.contrib.aiohttp import HTTPSPublicKeyRetriever
from atlassian_jwt_auth.key import PEM_FILE_TYPE
from atlassian_jwt_auth.tests import utils
from atlassian_jwt_auth.tests.test_public_key_provider import (
    get_expected_and_os_proxies_dict,
)


class DummyHTTPSPublicKeyRetriever(HTTPSPublicKeyRetriever):

    def set_headers(self, headers):
        self._session.get.return_value.headers.update(headers)

    def set_text(self, text):
        self._session.get.return_value.text.return_value = text

    def _get_session(self):
        session = Mock(spec=aiohttp.ClientSession)
        session.attach_mock(CoroutineMock(), 'get')

        resp = session.get.return_value
        resp.headers = CIMultiDict({"content-type": PEM_FILE_TYPE})
        resp.text = CoroutineMock(return_value='i-am-a-public-key')
        resp.raise_for_status = Mock(name='raise_for_status')
        return session


class BaseHTTPSPublicKeyRetrieverTestMixin(object):
    """Tests for aiohttp.HTTPSPublicKeyRetriever class for RS256 algorithm"""

    def setUp(self):
        self._private_key_pem = self.get_new_private_key_in_pem_format()
        self._public_key_pem = utils.get_public_key_pem_for_private_key_pem(
            self._private_key_pem)
        self.base_url = 'https://example.com'

    async def test_retrieve(self):
        """Check if retrieve method returns public key"""
        retriever = DummyHTTPSPublicKeyRetriever(self.base_url)
        retriever.set_text(self._public_key_pem)
        self.assertEqual(
            await retriever.retrieve('example/eg'),
            self._public_key_pem)

    async def test_retrieve_with_charset_in_content_type_h(self):
        """Check if retrieve method correctly checks content-type"""
        headers = {'content-type': 'application/x-pem-file;charset=UTF-8'}
        retriever = DummyHTTPSPublicKeyRetriever(self.base_url)
        retriever.set_text(self._public_key_pem)
        retriever.set_headers(headers)

        self.assertEqual(
            await retriever.retrieve('example/eg'),
            self._public_key_pem)

    async def test_retrieve_fails_with_different_content_type(self):
        """
        Check if retrieve method raises an error for incorrect content-type
        """
        headers = {'content-type': 'different/not-supported'}
        retriever = DummyHTTPSPublicKeyRetriever(self.base_url)
        retriever.set_text(self._public_key_pem)
        retriever.set_headers(headers)

        with self.assertRaises(ValueError):
            await retriever.retrieve('example/eg')

    async def test_retrieve_session_uses_env_proxy(self):
        """ tests that the underlying session makes use of environmental
            proxy configured.
        """
        proxy_location = 'https://example.proxy'
        key_id = 'example/eg'
        expected_proxies, proxy_dict = get_expected_and_os_proxies_dict(
            proxy_location)
        with mock.patch.dict(os.environ, proxy_dict, clear=True):
            retriever = DummyHTTPSPublicKeyRetriever(self.base_url)
            self.assertEqual(retriever._proxies, expected_proxies)
            await retriever.retrieve(key_id)
            retriever._session.get.assert_called_once_with(
                f'{self.base_url}/{key_id}', headers={'accept': PEM_FILE_TYPE},
                proxy=expected_proxies[self.base_url.split(':')[0]]
            )


class RS256HTTPSPublicKeyRetrieverTest(utils.RS256KeyTestMixin,
                                       BaseHTTPSPublicKeyRetrieverTestMixin,
                                       TestCase):
    """Tests for aiohttp.HTTPSPublicKeyRetriever class for RS256 algorithm"""


class ES256HTTPSPublicKeyRetrieverTest(utils.RS256KeyTestMixin,
                                       BaseHTTPSPublicKeyRetrieverTestMixin,
                                       TestCase):
    """Tests for aiohttp.HTTPSPublicKeyRetriever class for ES256 algorithm"""
