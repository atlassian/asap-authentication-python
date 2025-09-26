from typing import Any, Optional

from django.conf import settings as django_settings
from django.http import HttpRequest, HttpResponse, HttpResponseForbidden

from ..common.backend import Backend


class DjangoBackend(Backend):
    def get_authorization_header(self, request: Optional[HttpRequest] = None) -> bytes:
        if request is None:
            raise ValueError("No request available")

        return request.META.get("HTTP_AUTHORIZATION", b"")

    def get_401_response(
        self,
        data: Optional[Any] = None,
        headers: Optional[Any] = None,
        request: Optional[HttpRequest] = None,
    ) -> HttpResponse:
        if headers is None:
            headers = {}

        headers.update(self.default_headers_401)

        response = HttpResponse(content=data, status=401)
        for k, v in headers.items():
            response[k] = v

        return response

    def get_403_response(
        self,
        data: Optional[Any] = None,
        headers: Optional[Any] = None,
        request: Optional[HttpRequest] = None,
    ) -> HttpResponse:
        if headers is None:
            headers = {}

        response = HttpResponseForbidden(data)
        for k, v in headers.items():
            response[k] = v

        return response

    def set_asap_claims_for_request(self, request: HttpRequest, claims: Any) -> None:
        request.asap_claims = claims

    @property
    def settings(self):
        settings = {}
        settings.update(self.default_settings)

        for k in settings.keys():
            value = getattr(django_settings, k, None)
            if value is None:
                continue

            settings[k] = value

        return self._process_settings(settings)
