import base64
import cgi
import os
import re
import sys

import cachecontrol
import cryptography.hazmat.backends
from cryptography.hazmat.primitives import serialization
import jwt
import requests

if sys.version_info[0] >= 3:
    from urllib.parse import unquote_plus
else:
    from urllib import unquote_plus


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


class HTTPSPublicKeyRetriever(object):

    """ This class retrieves public key from a https location based upon the
         given key id.
    """

    def __init__(self, base_url):
        if not base_url.startswith('https://'):
            raise ValueError('The base url must start with https://')
        if not base_url.endswith('/'):
            base_url += '/'
        self.base_url = base_url
        self._session = None

    def _get_session(self):
        if self._session is not None:
            return self._session
        session = requests.Session()
        session.mount('https://', cachecontrol.CacheControlAdapter())
        self._session = session
        return self._session

    def retrieve(self, key_identifier, **requests_kwargs):
        """ returns the public key for given key_identifier. """
        if not isinstance(key_identifier, KeyIdentifier):
            key_identifier = KeyIdentifier(key_identifier)
        PEM_FILE_TYPE = 'application/x-pem-file'
        url = self.base_url + key_identifier.key_id
        session = self._get_session()
        resp = session.get(url,
                           headers={'accept': PEM_FILE_TYPE},
                           **requests_kwargs)
        resp.raise_for_status()
        media_type = cgi.parse_header(resp.headers['content-type'])[0]
        if media_type.lower() != PEM_FILE_TYPE.lower():
            raise ValueError("Invalid content-type, '%s', for url '%s' ." %
                             (resp.headers['content-type'], url))
        return resp.text


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
