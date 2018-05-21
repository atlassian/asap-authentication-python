from flask import Response, current_app, g, request as current_req

from ..common.backend import Backend


class FlaskBackend(Backend):
    def get_authorization_header(self, request=None):
        if request is None:
            request = current_req

        return request.headers.get('AUTHORIZATION', '')

    def get_401_response(self, data=None, headers=None, request=None):
        if headers is None:
            headers = {}

        headers.update(self.default_headers_401)

        return Response(data, status=401, headers=headers)

    def get_403_response(self, data=None, headers=None, request=None):
        return Response(data, status=403, headers=headers)

    def set_asap_claims_for_request(self, request, claims):
        g.asap_claims = claims

    @property
    def settings(self):
        settings = {}

        settings.update(self.default_settings)

        for k in settings.keys():
            value = current_app.config.get(k)
            if value is None:
                continue

            settings[k] = value

        return self._process_settings(settings)
