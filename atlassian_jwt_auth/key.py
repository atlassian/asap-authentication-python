import base64
import cgi
import logging
import os
import re
import sys

import cachecontrol
import cryptography.hazmat.backends
import jwt
import requests
from cryptography.hazmat.primitives import serialization
from requests.exceptions import RequestException

if sys.version_info[0] >= 3:
    from urllib.parse import unquote_plus
else:
    from urllib import unquote_plus

PEM_FILE_TYPE = 'application/x-pem-file'
logger = logging.getLogger(__name__)


class KeyIdentifier(object):

    """ This class represents a key identifier """

    def __init__(self, identifier):
        self.__key_id = validate_key_identifier(identifier)

    @property
    def key_id(self):
        return self.__key_id


def validate_key_identifier(identifier):
    """ returns a validated key identifier. """
    regex = re.compile('^[\w.\-\+/]*$')
    _error_msg = 'Invalid key identifier %s' % identifier
    if not identifier:
        raise ValueError(_error_msg)
    if not regex.match(identifier):
        raise ValueError(_error_msg)
    normalised = os.path.normpath(identifier)
    if normalised != identifier:
        raise ValueError(_error_msg)
    if normalised.startswith('/'):
        raise ValueError(_error_msg)
    if '..' in normalised:
        raise ValueError(_error_msg)
    return identifier


def _get_key_id_from_jwt_header(a_jwt):
    """ returns the key identifier from a jwt header. """
    header = jwt.get_unverified_header(a_jwt)
    return KeyIdentifier(header['kid'])


class BasePublicKeyRetriever(object):
    """Base class for getting a public key"""

    def retrieve(self, key_identifier, **kwargs):
        raise NotImplementedError()


class HTTPSPublicKeyRetriever(BasePublicKeyRetriever):

    """ This class retrieves public key from a https location based upon the
         given key id.
    """

    def __init__(self, base_url):
        self.base_url = self._validate_baseurl(base_url)
        self._session = self._get_session()

    def _validate_baseurl(self, base_url):
        if base_url is None or not base_url.startswith('https://'):
            raise ValueError('The base url must start with https://')
        if not base_url.endswith('/'):
            base_url += '/'

        return base_url

    def _get_session(self):
        session = requests.Session()
        session.mount('https://', cachecontrol.CacheControlAdapter())

        return session

    def retrieve(self, key_identifier, **requests_kwargs):
        """ returns the public key for given key_identifier. """
        if not isinstance(key_identifier, KeyIdentifier):
            key_identifier = KeyIdentifier(key_identifier)

        url = self.base_url + key_identifier.key_id
        return self._retrieve(url, requests_kwargs)

    def _retrieve(self, url, requests_kwargs):
        resp = self._session.get(url, headers={'accept': PEM_FILE_TYPE},
                                 **requests_kwargs)
        resp.raise_for_status()
        self._check_content_type(url, resp.headers['content-type'])
        return resp.text

    def _check_content_type(self, url, content_type):
        media_type = cgi.parse_header(content_type)[0]

        if media_type.lower() != PEM_FILE_TYPE.lower():
            raise ValueError("Invalid content-type, '%s', for url '%s' ." %
                             (content_type, url))


class HTTPSMultiPublicKeyRetriever(HTTPSPublicKeyRetriever):
    def __init__(self, keystore_urls):
        self.keystore_urls = self._validate_keystore_urls(keystore_urls)
        self._session = self._get_session()

    def _validate_keystore_urls(self, keystore_urls):
        if not isinstance(keystore_urls, list):
            raise ValueError('keystore_urls should be a list of urls')

        _keystore_urls = []
        for url in keystore_urls:
            _keystore_urls.append(self._validate_baseurl(url))

        return _keystore_urls

    def retrieve(self, key_identifier, **requests_kwargs):
        for url in self.keystore_urls:
            if not isinstance(key_identifier, KeyIdentifier):
                key_identifier = KeyIdentifier(key_identifier)

            key_url = url + key_identifier.key_id

            try:
                return self._retrieve(key_url, requests_kwargs)
            except RequestException as e:
                logger.warn('Unable to retrieve public key from store',
                            extra={'underlying_error': str(e),
                                   'keystore_url': key_url})
        else:
            raise KeyError('Cannot load key from keystore(s)')


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
            raise ValueError('Unrecognised data uri format.')
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
