from collections import namedtuple
from typing import Any

from ..common.asap import _process_asap_token
from .backend import WSGIBackend

Request = namedtuple("Request", ["environ", "start_response"])


class ASAPMiddleware(object):
    def __init__(self, handler: Any, settings: Any) -> None:
        self._next = handler
        self._backend = WSGIBackend(settings)
        self._verifier = self._backend.get_verifier()

    def __call__(self, environ: Any, start_response: Any):
        settings = self._backend.settings
        request = Request(environ, start_response)
        error_response = _process_asap_token(
            request, self._backend, settings, verifier=self._verifier
        )
        if error_response is not None:
            return error_response

        return self._next(environ, start_response)
