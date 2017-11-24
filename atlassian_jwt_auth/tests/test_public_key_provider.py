import unittest

import mock
import requests

from atlassian_jwt_auth.key import (
    HTTPSPublicKeyRetriever,
    HTTPSMultiRepositoryPublicKeyRetriever,
)
from atlassian_jwt_auth.tests import utils


class BaseHTTPSPublicKeyRetrieverTest(object):
    """ tests for the HTTPSPublicKeyRetriever class. """

    def create_retriever(self, url):
        """ returns a public key retriever created using the given url. """
        return HTTPSPublicKeyRetriever(url)

    def setUp(self):
        self._private_key_pem = self.get_new_private_key_in_pem_format()
        self._public_key_pem = utils.get_public_key_pem_for_private_key_pem(
            self._private_key_pem)
        self.base_url = 'https://example.com'

    def test_https_public_key_retriever_does_not_support_http_url(self):
        """ tests that HTTPSPublicKeyRetriever does not support http://
            base urls.
        """
        with self.assertRaises(ValueError):
            retriever = self.create_retriever('http://example.com')

    def test_https_public_key_retriever_does_not_support_none_url(self):
        """ tests that HTTPSPublicKeyRetriever does not support None
            base urls.
        """
        with self.assertRaises(ValueError):
            retriever = self.create_retriever(None)

    def test_https_public_key_retriever_supports_https_url(self):
        """ tests that HTTPSPublicKeyRetriever supports https://
            base urls.
        """
        retriever = self.create_retriever(self.base_url)

    @mock.patch.object(requests.Session, 'get')
    def test_retrieve(self, mock_get_method):
        """ tests that the retrieve method works expected. """
        _setup_mock_response_for_retriever(
            mock_get_method, self._public_key_pem)
        retriever = self.create_retriever(self.base_url)
        self.assertEqual(
            retriever.retrieve('example/eg'),
            self._public_key_pem)

    @mock.patch.object(requests.Session, 'get')
    def test_retrieve_with_charset_in_content_type_h(self, mock_get_method):
        """ tests that the retrieve method works expected when there is
            a charset in the response content-type header.
        """
        headers = {'content-type': 'application/x-pem-file;charset=UTF-8'}
        _setup_mock_response_for_retriever(
            mock_get_method, self._public_key_pem, headers)
        retriever = self.create_retriever(self.base_url)
        self.assertEqual(
            retriever.retrieve('example/eg'),
            self._public_key_pem)

    @mock.patch.object(requests.Session, 'get')
    def test_retrieve_fails_with_different_content_type(self, mock_get_method):
        """ tests that the retrieve method fails when the response is for a
            media type that is not supported.
        """
        headers = {'content-type': 'different/not-supported'}
        _setup_mock_response_for_retriever(
            mock_get_method, self._public_key_pem, headers)
        retriever = self.create_retriever(self.base_url)
        with self.assertRaises(ValueError):
            retriever.retrieve('example/eg')

    @mock.patch.object(requests.Session, 'get',
                       side_effect=requests.exceptions.HTTPError(
                           mock.Mock(response=mock.Mock(status_code=403)),
                           'forbidden'))
    def test_retrieve_fails_with_forbidden_error(self, mock_get_method):
        """ tests that the retrieve method fails when the response is an
        403 forbidden error.
        """
        _setup_mock_response_for_retriever(
            mock_get_method, self._public_key_pem)
        retriever = self.create_retriever(self.base_url)
        with self.assertRaises(ValueError):
            retriever.retrieve('example/eg')


class BaseHTTPSMultiRepositoryPublicKeyRetrieverTest(
        BaseHTTPSPublicKeyRetrieverTest):
    """ tests for the HTTPSMultiRepositoryPublicKeyRetriever class. """

    def create_retriever(self, url):
        """ returns a public key retriever created using the given url. """
        return HTTPSMultiRepositoryPublicKeyRetriever([url])

    def setUp(self):
        self._private_key_pem = self.get_new_private_key_in_pem_format()
        self._public_key_pem = utils.get_public_key_pem_for_private_key_pem(
            self._private_key_pem)
        self.keystore_urls = ['https://example.com', 'https://example.ly']
        self.base_url = self.keystore_urls[0]

    def test_https_multi_public_key_retriever_does_not_support_strings(self):
        """ tests that HTTPSMultiRepositoryPublicKeyRetriever does not
            support a string key repository url.
        """
        with self.assertRaises(TypeError):
            HTTPSMultiRepositoryPublicKeyRetriever('https://example.com')

    @mock.patch.object(requests.Session, 'get')
    def test_retrieve(self, mock_get_method):
        """ tests that the retrieve method works expected. """
        _setup_mock_response_for_retriever(
            mock_get_method, self._public_key_pem)
        retriever = HTTPSMultiRepositoryPublicKeyRetriever(self.keystore_urls)
        self.assertEqual(
            retriever.retrieve('example/eg'),
            self._public_key_pem)


def _setup_mock_response_for_retriever(
        mock_method, public_key_pem, headers=None):
    """ returns a setup mock response for use with a https public key
        retriever.
    """
    if headers is None:
        headers = {'content-type': 'application/x-pem-file'}
    mock_response = mock.Mock()
    mock_response.headers = headers
    mock_response.text = public_key_pem
    mock_method.return_value = mock_response
    return mock_method


class HTTPSPublicKeyRetrieverRS256Test(BaseHTTPSPublicKeyRetrieverTest,
                                       utils.RS256KeyTestMixin,
                                       unittest.TestCase):
    pass


class HTTPSPublicKeyRetrieverES256Test(BaseHTTPSPublicKeyRetrieverTest,
                                       utils.ES256KeyTestMixin,
                                       unittest.TestCase):
    pass


class HTTPSMultiRepositoryPublicKeyRetrieverRS256Test(
        BaseHTTPSMultiRepositoryPublicKeyRetrieverTest,
        utils.RS256KeyTestMixin,
        unittest.TestCase):
    pass


class HTTPSMultiRepositoryPublicKeyRetrieverES256Test(
        BaseHTTPSMultiRepositoryPublicKeyRetrieverTest,
        utils.ES256KeyTestMixin,
        unittest.TestCase):
    pass
