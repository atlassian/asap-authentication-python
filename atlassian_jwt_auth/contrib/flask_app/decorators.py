from functools import wraps

from flask import Response, current_app, g, request as current_req

from ..server.helpers import _requires_asap, Backend


class FlaskBackend(Backend):

    def get_request_header_value(self, request, header_name):
        return request.headers.get(header_name, None)

    def get_setting(self, setting, default=None):
        return current_app.config.get(setting, default)


def requires_asap(f):
    """
    Wrapper for Flask endpoints to make them require asap authentication to
    access.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        backend = FlaskBackend()
        err_response = _requires_asap(
            verifier=backend.get_verifier(),
            auth=backend.get_request_auth_header_value(current_req),
            parse_jwt_func=backend.parse_jwt,
            build_response_func=_build_response,
            asap_claim_holder=g,
        )
        if err_response is None:
            return f(*args, **kwargs)
        return err_response

    return decorated


def _build_response(message, status, headers=None):
    return Response(message, status=status, headers=headers)
