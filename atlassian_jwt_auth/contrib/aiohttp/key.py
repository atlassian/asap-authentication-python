import asyncio
import urllib.parse
from asyncio import AbstractEventLoop
from typing import Any, Awaitable, Dict, Optional

import aiohttp

from atlassian_jwt_auth.exceptions import PublicKeyRetrieverException
from atlassian_jwt_auth.key import PEM_FILE_TYPE
from atlassian_jwt_auth.key import HTTPSPublicKeyRetriever as _HTTPSPublicKeyRetriever


class HTTPSPublicKeyRetriever(_HTTPSPublicKeyRetriever):
    """A class for retrieving JWT public keys with aiohttp"""

    _class_session = None

    def __init__(
        self, base_url: str, *, loop: Optional[AbstractEventLoop] = None
    ) -> None:
        if loop is None:
            loop = asyncio.get_event_loop()
        self.loop = loop
        super().__init__(base_url)

    def _get_session(self) -> aiohttp.ClientSession:  # type: ignore[override]
        if HTTPSPublicKeyRetriever._class_session is None:
            HTTPSPublicKeyRetriever._class_session = aiohttp.ClientSession(
                loop=self.loop
            )
        return HTTPSPublicKeyRetriever._class_session

    def _convert_proxies_to_proxy_arg(
        self, url: str, requests_kwargs: Dict[Any, Any]
    ) -> Dict[str, Any]:
        """returns a modified requests_kwargs dict that contains proxy
        information in a form that aiohttp accepts
        (it wants proxy information instead of a dict of proxies).
        """
        proxy = None
        if "proxies" in requests_kwargs:
            scheme = urllib.parse.urlparse(url).scheme
            proxy = requests_kwargs["proxies"].get(scheme, None)
            del requests_kwargs["proxies"]
            requests_kwargs["proxy"] = proxy
        return requests_kwargs

    async def _retrieve(
        self, url: str, requests_kwargs: Dict[Any, Any]
    ) -> Awaitable[str]:
        requests_kwargs = self._convert_proxies_to_proxy_arg(url, requests_kwargs)
        try:
            resp = await self._session.get(
                url,
                headers={
                    "accept":  # type: ignore[misc]
                    PEM_FILE_TYPE
                },
                **requests_kwargs,
            )
            resp.raise_for_status()
            self._check_content_type(url, resp.headers["content-type"])
            return await resp.text()
        except aiohttp.ClientError as e:
            status_code = getattr(e, "code", None)
            raise PublicKeyRetrieverException(e, status_code=status_code)
