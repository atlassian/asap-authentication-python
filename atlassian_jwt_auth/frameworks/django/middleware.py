from ..common.utils import process_asap_token
from .backend import DjangoBackend


def asap_middleware(get_response):
    """Middleware to enable ASAP for all requests"""
    backend = DjangoBackend()

    def middleware(request):
        error_response = process_asap_token(request, backend)
        if error_response:
            return error_response

        return get_response(request)

    return middleware


class OldStyleASAPMiddleware(object):
    """Middleware to enable ASAP for all requests (for legacy applications
    using MIDDLEWARE_CLASSES)"""

    def __init__(self):
        self.backend = DjangoBackend()

    def process_request(self, request):
        error_response = process_asap_token(request, self.backend)
        if error_response:
            return error_response
