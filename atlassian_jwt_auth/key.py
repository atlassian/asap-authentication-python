import os
import re

import requests


class KeyIdentifier(object):

    """ This class represents a key identifier """

    def __init__(self, identifier):
        self.key_id = validate_key_identifier(identifier)


def validate_key_identifier(self, identifier):
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
    return identifier


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

    def retrieve(self, key_identifier):
        """ returns the public key for given key_identifier. """
        if not isinstance(key_identifier, KeyIdentifier):
            key_identifier = KeyIdentifier(key_identifier)
        PEM_FILE_TYPE = 'application/x-pem-file'
        url = self.base_url + key_identifier.key_id
        resp = requests.get(url,
                            headers={'accept': PEM_FILE_TYPE})
        resp.raise_for_status()
        if resp.headers['content-type'] != PEM_FILE_TYPE:
            raise ValueError("Invalid content-type, '%s', for url '%s' ." %
                             (resp.headers['content-type'], url))
        return resp.text
