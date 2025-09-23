import unittest
from typing import Any, Dict

from atlassian_jwt_auth.contrib.aiohttp.auth import JWTAuth, create_jwt_auth
from atlassian_jwt_auth.contrib.tests import test_requests
from atlassian_jwt_auth.tests import utils


class BaseAuthTest(test_requests.BaseRequestsTest):
    """ tests for the contrib.aiohttp.JWTAuth class """
    auth_cls = JWTAuth

    def _get_auth_header(self, auth) -> bytes:
        return auth.encode().encode('latin1')

    def create_jwt_auth(self, *args: Any, **kwargs: Dict):
        return create_jwt_auth(*args, **kwargs)


class RequestsRS256Test(BaseAuthTest,
                        utils.RS256KeyTestMixin,
                        unittest.TestCase):
    pass


class RequestsES256Test(BaseAuthTest,
                        utils.ES256KeyTestMixin,
                        unittest.TestCase):
    pass
