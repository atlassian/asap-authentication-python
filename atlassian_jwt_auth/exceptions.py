class ASAPAuthenticationException(ValueError):
    """Base class for exceptions raised by this library

    Inherits from ValueError to maintain backward compatibility
    with clients that caught ValueError previously.
    """


class PublicKeyRetrieverException(ASAPAuthenticationException):
    """Raise when there are issues retrieving the public key"""


class PrivateKeyRetrieverException(ASAPAuthenticationException):
    """Raise when there are issues retrieving the private key"""


class KeyIdentifierException(ASAPAuthenticationException):
    """Raise when there are issues validating the key identifier"""
