from functools import wraps
from django.http import HttpResponse, HttpResponseForbidden
from django.conf import settings

import jwt

from atlassian_jwt_auth.contrib.django_app.auth import ASAPAuthBackend


class HttpResponseNotAuthorized(HttpResponse):
    status_code = 401


def _get_asap_user(request, issuers=None):
    auth_header = request.META.get('HTTP_AUTHORIZATION', '').split(' ', 1)

    if len(auth_header) < 2 or auth_header[0].lower() != 'bearer':
        return None, HttpResponseNotAuthorized(
            'This endpoint requires ASAP authentication.'
        )

    token = auth_header[1]
    user = ASAPAuthBackend.authenticate(token=token)
    if user is None:
        return None, HttpResponseNotAuthorized(
            'This endpoint requires ASAP authentication.'
        )

    claims = jwt.decode(token, verify=False)
    issuers = issuers or settings.ASAP_VALID_ISSUERS

    if issuers and claims.get('iss') not in issuers:
        return None, HttpResponseForbidden(
            'ASAP issuer is not allowed to access this endpoint'
        )

    return user, None


def asap_allowed(view_func, issuers=None):
    """Decorator which allows the user to authenticate with a valid
    ASAP token"""
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_authenticated():
            return None

        user, error_resp = _get_asap_user(request, issuers)

        if user:
            request.user = user

        return view_func(request, *args, **kwargs)

    return _wrapped_view


def asap_required(view_func, issuers=None):
    """Decorator which ensures the user has authenticated with a valid
    ASAP token"""

    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        user, error_resp = _get_asap_user(request, issuers)

        if error_resp:
            return error_resp

        request.user = user
        return view_func(request, *args, **kwargs)

    return _wrapped_view
