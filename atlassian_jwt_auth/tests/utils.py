from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

import atlassian_jwt_auth


def get_new_rsa_private_key_in_pem_format():
    """ returns a new rsa key in pem format. """
    private_key = rsa.generate_private_key(
        key_size=2048, backend=default_backend(), public_exponent=65537)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


def get_public_key_pem_for_private_key_pem(private_key_pem):
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def get_example_jwt_auth_signer(**kwargs):
    """ returns an example jwt_auth_signer instance. """
    issuer = kwargs.get('issuer', 'egissuer')
    key_id = kwargs.get('key_id', '%s/a' % issuer)
    key = kwargs.get(
        'private_key_pem', get_new_rsa_private_key_in_pem_format())
    algorithm = kwargs.get('algorithm', 'RS256')
    return atlassian_jwt_auth.create_signer(
        issuer, key_id, key, algorithm=algorithm)


class BaseJWTAlgorithmTestMixin(object):

    """ A mixin class to make testing different support for different
        jwt algorithms easier.
    """

    def get_new_private_key_in_pem_format(self):
        """ returns a new private key in pem format. """
        raise NotImplementedError("not implemented.")


class RS256KeyTestMixin(object):

    """ Private rs256 test mixin. """

    @property
    def algorithm(self):
        return 'RS256'

    def get_new_private_key_in_pem_format(self):
        return get_new_rsa_private_key_in_pem_format()


class ES256KeyTestMixin(object):

    """ Private es256 test mixin. """

    @property
    def algorithm(self):
        return 'ES256'

    def get_new_private_key_in_pem_format(self):
        private_key = ec.generate_private_key(
            ec.SECP256R1(), default_backend())
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
