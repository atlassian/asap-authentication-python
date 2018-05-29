from atlassian_jwt_auth.exceptions import ASAPAuthenticationException


class NoTokenProvidedError(ASAPAuthenticationException):
    pass
