import base64
import logging
import os
import re
from urllib.parse import unquote_plus
from email.message import EmailMessage

import cachecontrol
import cryptography.hazmat.backends
import jwt
import requests
import requests.utils
from cryptography.hazmat.primitives import serialization
from requests.exceptions import RequestException, ConnectionError

from atlassian_jwt_auth.exceptions import (KeyIdentifierException,
                                           PublicKeyRetrieverException,
                                           PrivateKeyRetrieverException)


PEM_FILE_TYPE = 'application/x-pem-file'


class KeyIdentifier(object):

    """ This class represents a key identifier """

    def __init__(self, identifier):
        self.__key_id = validate_key_identifier(identifier)

    @property
    def key_id(self):
        return self.__key_id


def validate_key_identifier(identifier):
    """ returns a validated key identifier. """
    regex = re.compile(r'^[\w.\-\+/]*$')
    _error_msg = 'Invalid key identifier %s' % identifier
    if not identifier:
        raise KeyIdentifierException(_error_msg)
    if not regex.match(identifier):
        raise KeyIdentifierException(_error_msg)
    normalised = os.path.normpath(identifier)
    if normalised != identifier:
        raise KeyIdentifierException(_error_msg)
    if normalised.startswith('/'):
        raise KeyIdentifierException(_error_msg)
    if '..' in normalised:
        raise KeyIdentifierException(_error_msg)
    return identifier


def _get_key_id_from_jwt_header(a_jwt):
    """ returns the key identifier from a jwt header. """
    header = jwt.get_unverified_header(a_jwt)
    return KeyIdentifier(header['kid'])


class BasePublicKeyRetriever(object):
    """ Base class for retrieving a public key. """

    def retrieve(self, key_identifier, **kwargs):
        raise NotImplementedError()


class HTTPSPublicKeyRetriever(BasePublicKeyRetriever):

    """ This class retrieves public key from a https location based upon the
         given key id.
    """
    # Use a static requests session, reused/shared by all instances of
    # HTTPSPublicKeyRetriever:
    _class_session = None

    def __init__(self, base_url):
        if base_url is None or not base_url.startswith('https://'):
            raise PublicKeyRetrieverException(
                'The base url must start with https://')
        if not base_url.endswith('/'):
            base_url += '/'
        self.base_url = base_url
        self._session = self._get_session()
        self._proxies = requests.utils.get_environ_proxies(self.base_url)

    def _get_session(self):
        if HTTPSPublicKeyRetriever._class_session is None:
            session = cachecontrol.CacheControl(requests.Session())
            session.trust_env = False
            HTTPSPublicKeyRetriever._class_session = session
        return HTTPSPublicKeyRetriever._class_session

    def retrieve(self, key_identifier, **requests_kwargs):
        """ returns the public key for given key_identifier. """
        if not isinstance(key_identifier, KeyIdentifier):
            key_identifier = KeyIdentifier(key_identifier)
        if self._proxies and 'proxies' not in requests_kwargs:
            requests_kwargs['proxies'] = self._proxies
        url = self.base_url + key_identifier.key_id
        try:
            return self._retrieve(url, requests_kwargs)
        except requests.RequestException as e:
            try:
                status_code = e.response.status_code
            except AttributeError:
                status_code = None
            raise PublicKeyRetrieverException(e, status_code=status_code)

    def _retrieve(self, url, requests_kwargs):
        resp = self._session.get(url, headers={'accept': PEM_FILE_TYPE},
                                 **requests_kwargs)
        resp.raise_for_status()
        self._check_content_type(url, resp.headers['content-type'])
        return resp.text

    def _check_content_type(self, url, content_type):
        msg = EmailMessage()
        msg['content-type'] = content_type
        media_type = msg.get_content_type()

        if media_type.lower() != PEM_FILE_TYPE.lower():
            raise PublicKeyRetrieverException(
                "Invalid content-type, '%s', for url '%s' ." %
                (content_type, url))


class HTTPSMultiRepositoryPublicKeyRetriever(BasePublicKeyRetriever):
    """ This class retrieves public key from the supplied https key
        repository locations based upon key ids.
    """

    def __init__(self, key_repository_urls):
        if not isinstance(key_repository_urls, list):
            raise TypeError('keystore_urls must be a list of urls.')
        self._retrievers = self._create_retrievers(key_repository_urls)

    def _create_retrievers(self, key_repository_urls):
        return [HTTPSPublicKeyRetriever(url) for url
                in key_repository_urls]

    def handle_retrieval_exception(self, retriever, exception):
        """ Handles working with exceptions encountered during key
            retrieval.
        """
        if isinstance(exception, PublicKeyRetrieverException):
            original_exception = getattr(
                exception, 'original_exception', None)
            if isinstance(original_exception, ConnectionError):
                return
            if exception.status_code is None or exception.status_code < 500:
                raise

    def retrieve(self, key_identifier, **requests_kwargs):
        for retriever in self._retrievers:
            try:
                return retriever.retrieve(key_identifier, **requests_kwargs)
            except (RequestException, PublicKeyRetrieverException) as e:
                self.handle_retrieval_exception(retriever, e)
                logger = logging.getLogger(__name__)
                logger.warning(
                    'Unable to retrieve public key from store',
                    extra={'underlying_error': str(e),
                           'key repository': retriever.base_url})
        raise PublicKeyRetrieverException(
            'Cannot load key from key repositories')


class BasePrivateKeyRetriever(object):
    """ This is the base private key retriever class. """

    def load(self, issuer):
        """ returns the key identifier and private key pem found
            for the given issuer.
        """
        raise NotImplementedError('Not implemented.')


class DataUriPrivateKeyRetriever(BasePrivateKeyRetriever):
    """ This class can be used to retrieve the key identifier and
        private key from the supplied data uri.
    """

    def __init__(self, data_uri):
        self._data_uri = data_uri

    def load(self, issuer):
        if not self._data_uri.startswith('data:application/pkcs8;kid='):
            raise PrivateKeyRetrieverException('Unrecognised data uri format.')
        splitted = self._data_uri.split(';')
        key_identifier = KeyIdentifier(unquote_plus(
            splitted[1][len('kid='):]))
        key_data = base64.b64decode(splitted[-1].split(',')[-1])
        key = serialization.load_der_private_key(
            key_data,
            password=None,
            backend=cryptography.hazmat.backends.default_backend())
        private_key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return key_identifier, private_key_pem.decode('utf-8')


class StaticPrivateKeyRetriever(BasePrivateKeyRetriever):
    """ This class simply returns the key_identifier and private_key_pem
        initially provided to it in calls to load.
    """

    def __init__(self, key_identifier, private_key_pem):
        if not isinstance(key_identifier, KeyIdentifier):
            key_identifier = KeyIdentifier(key_identifier)

        self.key_identifier = key_identifier
        self.private_key_pem = private_key_pem

    def load(self, issuer):
        return self.key_identifier, self.private_key_pem


class FilePrivateKeyRetriever(BasePrivateKeyRetriever):
    """ This class can be used to retrieve the latest key identifier and
        private key for a given issuer found under its private key
        repository path.
    """

    def __init__(self, private_key_repository_path):
        self.private_key_repository = FilePrivateKeyRepository(
            private_key_repository_path)

    def load(self, issuer):
        key_identifier = self._find_last_key_id(issuer)
        private_key_pem = self.private_key_repository.load_key(key_identifier)
        return key_identifier, private_key_pem

    def _find_last_key_id(self, issuer):
        key_identifiers = list(
            self.private_key_repository.find_valid_key_ids(issuer))

        if key_identifiers:
            return key_identifiers[-1]
        else:
            raise IOError('Issuer has no valid keys: %s' % issuer)


class FilePrivateKeyRepository(object):
    """ This class represents a file backed private key repository. """

    def __init__(self, path):
        self.path = path

    def find_valid_key_ids(self, issuer):
        issuer_directory = os.path.join(self.path, issuer)
        for filename in sorted(os.listdir(issuer_directory)):
            if filename.endswith('.pem'):
                yield KeyIdentifier('%s/%s' % (issuer, filename))

    def load_key(self, key_identifier):
        key_filename = os.path.join(self.path, key_identifier.key_id)
        with open(key_filename, 'rb') as f:
            return f.read().decode('utf-8')
