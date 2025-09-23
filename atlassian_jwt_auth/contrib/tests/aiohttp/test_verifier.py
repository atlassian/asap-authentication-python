import asyncio
from asyncio import AbstractEventLoop
from typing import Optional, Any

try:
    from unittest import IsolatedAsyncioTestCase as TestCase
    from unittest.mock import AsyncMock as CoroutineMock, Mock
except ImportError:
    from asynctest import TestCase, CoroutineMock

from atlassian_jwt_auth.contrib.aiohttp import (HTTPSPublicKeyRetriever,
                                                JWTAuthVerifier)
from atlassian_jwt_auth.tests import test_verifier, utils


class SyncJWTAuthVerifier(JWTAuthVerifier):

    def __init__(self, *args: Any, loop: Optional[AbstractEventLoop]=None, **kwargs: Any) -> None:
        if loop is None:
            loop = asyncio.get_event_loop()
        self.loop = loop
        super().__init__(*args, **kwargs)

    def verify_jwt(self, *args:Any, **kwargs: Any):
        return self.loop.run_until_complete(
            super().verify_jwt(*args, **kwargs)
        )


class JWTAuthVerifierTestMixin(test_verifier.BaseJWTAuthVerifierTest):
    loop = None

    def _setup_mock_public_key_retriever(self, pub_key_pem: str) -> Mock:
        m_public_key_ret = CoroutineMock(spec=HTTPSPublicKeyRetriever)
        m_public_key_ret.retrieve.return_value = pub_key_pem.decode()
        return m_public_key_ret

    def _setup_jwt_auth_verifier(self, pub_key_pem: str, **kwargs: Any) -> SyncJWTAuthVerifier:
        m_public_key_ret = self._setup_mock_public_key_retriever(pub_key_pem)
        return SyncJWTAuthVerifier(m_public_key_ret, loop=self.loop, **kwargs)


class JWTAuthVerifierRS256Test(
        utils.RS256KeyTestMixin, JWTAuthVerifierTestMixin, TestCase):
    """Tests for aiohttp.JWTAuthVerifier class for RS256 algorithm"""


class JWTAuthVerifierES256Test(
        utils.ES256KeyTestMixin, JWTAuthVerifierTestMixin, TestCase):
    """Tests for aiohttp.JWTAuthVerifier class for ES256 algorithm"""
