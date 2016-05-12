import unittest

import mock
import requests

from atlassian_jwt_auth.key import HTTPSPublicKeyRetriever
from atlassian_jwt_auth.tests import utils


class BaseHTTPSPublicKeyRetrieverTest(object):
    """ tests for the HTTPSPublicKeyRetriever class. """

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
            retriever = HTTPSPublicKeyRetriever('http://example.com')

    def test_https_public_key_retriever_supports_https_url(self):
        """ tests that HTTPSPublicKeyRetriever supports https://
            base urls.
        """
        retriever = HTTPSPublicKeyRetriever(self.base_url)

    @mock.patch.object(requests.Session, 'get')
    def test_retrieve(self, mock_get_method):
        """ tests that the retrieve method works expected. """
        _setup_mock_response_for_retriever(
            mock_get_method, self._public_key_pem)
        retriever = HTTPSPublicKeyRetriever(self.base_url)
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
        retriever = HTTPSPublicKeyRetriever(self.base_url)
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
        retriever = HTTPSPublicKeyRetriever(self.base_url)
        with self.assertRaises(ValueError):
            retriever.retrieve('example/eg')


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
