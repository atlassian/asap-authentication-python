from typing import Any, Optional

from flask import Request, Response, current_app, g
from flask import request as current_req

from ..common.backend import Backend
from ..common.utils import SettingsDict


class FlaskBackend(Backend):
    def get_authorization_header(
            self, request: Optional[Request] = None) -> bytes:
        if request is None:
            request = current_req

        auth_header = request.headers.get('AUTHORIZATION', '')
        return auth_header.encode('utf-8') if isinstance(auth_header, str) else auth_header

    def get_401_response(self, data: Optional[Any] = None, headers: Optional[Any]
                         = None, request: Optional[Request] = None) -> Response:
        if headers is None:
            headers = {}

        headers.update(self.default_headers_401)

        return Response(data, status=401, headers=headers)

    def get_403_response(self, data: Optional[Any] = None, headers: Optional[Any]
                         = None, request: Optional[Request] = None) -> Response:
        return Response(data, status=403, headers=headers)

    def set_asap_claims_for_request(
            self, request: Request, claims: Any) -> None:
        g.asap_claims = claims

    @property
    def settings(self) -> SettingsDict:
        settings = {}

        settings.update(self.default_settings)

        for k in settings.keys():
            value = current_app.config.get(k)
            if value is None:
                continue

            settings[k] = value

        return self._process_settings(settings)
