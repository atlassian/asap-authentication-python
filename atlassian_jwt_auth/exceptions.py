class _WrappedException(object):
    """Allow wrapping exceptions in a new class while preserving the original
    as an attribute.

    Note that while Python 2 and 3 both have reasonable ways to handle this,
    they're mutually incompatible. This is a simple, portable approach that
    should be sufficient for most use cases.
    """

    def __init__(self, *args, **kwargs):
        wrapped_args = [arg for arg in args]

        if args:
            orig = args[0]
            if isinstance(orig, Exception):

                wrapped_args[0] = str(orig)
                self.original_exception = getattr(orig, 'original_exception',
                                                  orig)
        super(_WrappedException, self).__init__(*wrapped_args, **kwargs)


class _WithStatus(object):
    """Allow an optional status_code attribute on wrapped exceptions.

    This should allow inspecting HTTP-related errors without having to know
    details about the HTTP client library.
    """

    def __init__(self, *args, **kwargs):
        status_code = kwargs.pop('status_code', None)
        super(_WithStatus, self).__init__(*args, **kwargs)
        self.status_code = status_code


class ASAPAuthenticationException(_WrappedException, ValueError):
    """Base class for exceptions raised by this library

    Inherits from ValueError to maintain backward compatibility
    with clients that caught ValueError previously.
    """


class PublicKeyRetrieverException(_WithStatus, ASAPAuthenticationException):
    """Raise when there are issues retrieving the public key"""


class PrivateKeyRetrieverException(_WithStatus, ASAPAuthenticationException):
    """Raise when there are issues retrieving the private key"""


class KeyIdentifierException(ASAPAuthenticationException):
    """Raise when there are issues validating the key identifier"""


class JtiUniquenessException(ASAPAuthenticationException):
    """Raise when a JTI is seen more than once. """


class SubjectDoesNotMatchIssuerException(ASAPAuthenticationException):
    """Raise when the subject and issuer differ. """


class NoTokenProvidedError(ASAPAuthenticationException):
    """Raise when no token is provided"""
    pass
