from typing import Any, Callable, Optional

from django.http import HttpRequest

from ..common.asap import _process_asap_token
from .backend import DjangoBackend


def asap_middleware(get_response: Any) -> Callable:
    """Middleware to enable ASAP for all requests"""
    backend = DjangoBackend()
    settings = backend.settings
    _verifier = backend.get_verifier(settings=settings)

    def middleware(request: HttpRequest) -> Any:
        error_response = _process_asap_token(request, backend, settings,
                                             verifier=_verifier)
        if error_response is not None:
            return error_response

        return get_response(request)

    return middleware


class OldStyleASAPMiddleware(object):
    """Middleware to enable ASAP for all requests (for legacy applications
    using MIDDLEWARE_CLASSES)"""

    def __init__(self) -> None:
        self.backend = DjangoBackend()
        self.settings = self.backend.settings
        self._verifier = self.backend.get_verifier(settings=self.settings)

    def process_request(self, request: HttpRequest) -> Optional[str]:
        error_response = _process_asap_token(
            request, self.backend, self.settings, verifier=self._verifier
        )
        if error_response is not None:
            return error_response
        return None
