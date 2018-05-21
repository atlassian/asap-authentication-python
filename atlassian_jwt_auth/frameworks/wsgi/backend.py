from ..common.backend import Backend
from ..common.utils import SettingsDict


class WSGIBackend(Backend):
    def __init__(self, settings):
        self._settings = SettingsDict(settings)

    def get_authorization_header(self, request=None):
        if request is None:
            raise ValueError('No request available')

        return request.environ.get('HTTP_AUTHORIZATION', b'')

    def get_401_response(self, data=None, headers=None, request=None):
        if request is None:
            raise TypeError("request must have a value")

        if headers is None:
            headers = {}

        headers.update(self.default_headers_401)

        request.start_response('401 Unauthorized', list(headers.items()), None)
        return ""

    def get_403_response(self, data=None, headers=None, request=None):
        if request is None:
            raise TypeError("request must have a value")

        if headers is None:
            headers = {}

        request.start_response('403 Forbidden', list(headers.items()), None)
        return ""

    def set_asap_claims_for_request(self, request, claims):
        request.environ['ATL_ASAP_CLAIMS'] = claims

    @property
    def settings(self):
        settings = {}
        settings.update(self.default_settings)

        for k in settings.keys():
            value = getattr(self._settings, k, None)
            if value is None:
                continue

            settings[k] = value

        return self._process_settings(settings)
