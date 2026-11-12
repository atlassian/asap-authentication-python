import asyncio
import os
import unittest
from unittest import IsolatedAsyncioTestCase as TestCase
from unittest import mock
from unittest.mock import AsyncMock as CoroutineMock
from unittest.mock import Mock

import aiohttp
from aiohttp import web
from multidict import CIMultiDict

from atlassian_jwt_auth.contrib.aiohttp import HTTPSPublicKeyRetriever
from atlassian_jwt_auth.key import PEM_FILE_TYPE
from atlassian_jwt_auth.tests import utils
from atlassian_jwt_auth.tests.test_public_key_provider import (
    get_expected_and_os_proxies_dict,
)


class DummyHTTPSPublicKeyRetriever(HTTPSPublicKeyRetriever):
    def set_headers(self, headers):
        self._session.get.return_value.headers.update(headers)

    def set_text(self, text):
        self._session.get.return_value.text.return_value = text

    def _get_session(self) -> Mock:
        session = Mock(spec=aiohttp.ClientSession)
        session.attach_mock(CoroutineMock(), "get")

        resp = session.get.return_value
        resp.headers = CIMultiDict({"content-type": PEM_FILE_TYPE})
        resp.text = CoroutineMock(return_value="i-am-a-public-key")
        resp.raise_for_status = Mock(name="raise_for_status")
        return session


class BaseHTTPSPublicKeyRetrieverTestMixin:
    """Tests for aiohttp.HTTPSPublicKeyRetriever class for RS256 algorithm"""

    def setUp(self):
        self._private_key_pem = self.get_new_private_key_in_pem_format()
        self._public_key_pem = utils.get_public_key_pem_for_private_key_pem(
            self._private_key_pem
        )
        self.base_url = "https://example.com"

    async def test_retrieve(self):
        """Check if retrieve method returns public key"""
        retriever = DummyHTTPSPublicKeyRetriever(self.base_url)
        retriever.set_text(self._public_key_pem)
        self.assertEqual(await retriever.retrieve("example/eg"), self._public_key_pem)

    async def test_retrieve_with_charset_in_content_type_h(self):
        """Check if retrieve method correctly checks content-type"""
        headers = {"content-type": "application/x-pem-file;charset=UTF-8"}
        retriever = DummyHTTPSPublicKeyRetriever(self.base_url)
        retriever.set_text(self._public_key_pem)
        retriever.set_headers(headers)

        self.assertEqual(await retriever.retrieve("example/eg"), self._public_key_pem)

    async def test_retrieve_fails_with_different_content_type(self):
        """
        Check if retrieve method raises an error for incorrect content-type
        """
        headers = {"content-type": "different/not-supported"}
        retriever = DummyHTTPSPublicKeyRetriever(self.base_url)
        retriever.set_text(self._public_key_pem)
        retriever.set_headers(headers)

        with self.assertRaises(ValueError):
            await retriever.retrieve("example/eg")

    async def test_retrieve_session_uses_env_proxy(self):
        """tests that the underlying session makes use of environmental
        proxy configured.
        """
        proxy_location = "https://example.proxy"
        key_id = "example/eg"
        expected_proxies, proxy_dict = get_expected_and_os_proxies_dict(proxy_location)
        with mock.patch.dict(os.environ, proxy_dict, clear=True):
            retriever = DummyHTTPSPublicKeyRetriever(self.base_url)
            self.assertEqual(retriever._proxies, expected_proxies)
            await retriever.retrieve(key_id)
            retriever._session.get.assert_called_once_with(
                f"{self.base_url}/{key_id}",
                headers={"accept": PEM_FILE_TYPE},
                proxy=expected_proxies[self.base_url.split(":")[0]],
            )


class RS256HTTPSPublicKeyRetrieverTest(
    utils.RS256KeyTestMixin, BaseHTTPSPublicKeyRetrieverTestMixin, TestCase
):
    """Tests for aiohttp.HTTPSPublicKeyRetriever class for RS256 algorithm"""


class ES256HTTPSPublicKeyRetrieverTest(
    utils.RS256KeyTestMixin, BaseHTTPSPublicKeyRetrieverTestMixin, TestCase
):
    """Tests for aiohttp.HTTPSPublicKeyRetriever class for ES256 algorithm"""


class HTTPSPublicKeyRetrieverSessionLifecycleTest(unittest.TestCase):
    """Tests for aiohttp.HTTPSPublicKeyRetriever session reuse and invalidation."""

    def setUp(self):
        self.base_url = "https://example.com"
        self._reset_class_session()

    def tearDown(self):
        self._reset_class_session()

    @staticmethod
    def _reset_class_session():
        HTTPSPublicKeyRetriever._class_session = None
        HTTPSPublicKeyRetriever._class_session_loop = None

    def test_reuses_session_within_same_event_loop(self):
        async def run():
            first = HTTPSPublicKeyRetriever(self.base_url)
            second = HTTPSPublicKeyRetriever(self.base_url)
            try:
                self.assertIs(first._session, second._session)
            finally:
                await first._session.close()

        asyncio.run(run())

    def test_recreates_session_when_cached_session_is_closed(self):
        async def run():
            first = HTTPSPublicKeyRetriever(self.base_url)
            first_session = first._session
            await first_session.close()

            second = HTTPSPublicKeyRetriever(self.base_url)
            try:
                self.assertIsNot(second._session, first_session)
                self.assertFalse(second._session.closed)
            finally:
                await second._session.close()

        asyncio.run(run())

    def test_recreates_session_when_loop_differs(self):
        loop_one = asyncio.new_event_loop()
        loop_two = asyncio.new_event_loop()
        try:
            first = HTTPSPublicKeyRetriever(self.base_url, loop=loop_one)
            second = HTTPSPublicKeyRetriever(self.base_url, loop=loop_two)
            self.assertIsNot(first._session, second._session)
        finally:
            loop_one.run_until_complete(first._session.close())
            loop_two.run_until_complete(second._session.close())
            loop_one.close()
            loop_two.close()

    def test_recreates_session_when_cached_loop_is_closed(self):
        loop_one = asyncio.new_event_loop()
        loop_two = asyncio.new_event_loop()
        first = None
        second = None
        try:
            first = HTTPSPublicKeyRetriever(self.base_url, loop=loop_one)
            loop_one.close()
            self.assertFalse(first._session.closed)

            second = HTTPSPublicKeyRetriever(self.base_url, loop=loop_two)
            self.assertIsNot(first._session, second._session)
            self.assertFalse(second._session.closed)
        finally:
            if first is not None and not first._session.closed:
                if first._session.connector is not None:
                    first._session.connector._close()
                first._session._connector = None
            if second is not None:
                loop_two.run_until_complete(second._session.close())
            if not loop_one.is_closed():
                loop_one.close()
            loop_two.close()

    def test_recreates_session_across_sequential_event_loops(self):
        async def fetch_key():
            async def handler(_request):
                return web.Response(text="public-key", content_type=PEM_FILE_TYPE)

            app = web.Application()
            app.router.add_get("/key", handler)
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]

            retriever = HTTPSPublicKeyRetriever(self.base_url)
            try:
                body = await retriever._retrieve(f"http://127.0.0.1:{port}/key", {})
                return body, retriever._session
            finally:
                await retriever._session.close()
                await runner.cleanup()

        first_body, first_session = asyncio.run(fetch_key())
        second_body, second_session = asyncio.run(fetch_key())

        self.assertEqual(first_body, "public-key")
        self.assertEqual(second_body, "public-key")
        self.assertIsNot(first_session, second_session)
