from ..common.asap import _process_asap_token
from .backend import DjangoBackend


def asap_middleware(get_response):
    """Middleware to enable ASAP for all requests"""
    backend = DjangoBackend()
    settings = backend.settings

    def middleware(request):
        error_response = _process_asap_token(request, backend, settings)
        if error_response is not None:
            return error_response

        return get_response(request)

    return middleware


class OldStyleASAPMiddleware(object):
    """Middleware to enable ASAP for all requests (for legacy applications
    using MIDDLEWARE_CLASSES)"""

    def __init__(self):
        self.backend = DjangoBackend()
        self.settings = self.backend.settings

    def process_request(self, request):
        error_response = _process_asap_token(
            request, self.backend, self.settings
        )
        if error_response is not None:
            return error_response
