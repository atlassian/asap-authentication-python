import unittest
from typing import Any, Type

from atlassian_jwt_auth.auth import BaseJWTAuth
from atlassian_jwt_auth.contrib.aiohttp.auth import JWTAuth, create_jwt_auth
from atlassian_jwt_auth.contrib.tests import test_requests
from atlassian_jwt_auth.tests import utils


class BaseAuthTest(test_requests.BaseRequestsTest):
    """tests for the contrib.aiohttp.JWTAuth class"""

    auth_cls: Type[JWTAuth] = JWTAuth

    def _get_auth_header(self, auth) -> bytes:
        return auth.encode().encode("latin1")

    def create_jwt_auth(self, *args: Any, **kwargs: Any) -> BaseJWTAuth:
        return create_jwt_auth(*args, **kwargs)


class RequestsRS256Test(BaseAuthTest, utils.RS256KeyTestMixin, unittest.TestCase):
    pass


class RequestsES256Test(BaseAuthTest, utils.ES256KeyTestMixin, unittest.TestCase):
    pass
