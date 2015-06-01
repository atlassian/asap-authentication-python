import os
import re

from cachecontrol import CacheControlAdapter
from jwt.api_jwt import PyJWT
import requests


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
    payload, signing_input, header, signature = PyJWT()._load(a_jwt)
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
        session.mount('https://', CacheControlAdapter())
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
        if resp.headers['content-type'].lower() != PEM_FILE_TYPE.lower():
            raise ValueError("Invalid content-type, '%s', for url '%s' ." %
                             (resp.headers['content-type'], url))
        return resp.text
