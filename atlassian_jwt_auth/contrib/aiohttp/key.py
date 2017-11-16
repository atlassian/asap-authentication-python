import asyncio

import aiohttp

from atlassian_jwt_auth.exceptions import PublicKeyRetrieverException
from atlassian_jwt_auth.key import (
    PEM_FILE_TYPE,
    HTTPSPublicKeyRetriever as _HTTPSPublicKeyRetriever
)


class HTTPSPublicKeyRetriever(_HTTPSPublicKeyRetriever):
    """A class for retrieving JWT public keys with aiohttp"""

    def __init__(self, base_url, *, loop=None):
        if loop is None:
            loop = asyncio.get_event_loop()
        self.loop = loop
        super().__init__(base_url)

    def _get_session(self):
        return aiohttp.ClientSession(loop=self.loop)

    async def _retrieve(self, url, requests_kwargs):
        try:
            resp = await self._session.get(url, headers={'accept':
                                                         PEM_FILE_TYPE},
                                           **requests_kwargs)
            resp.raise_for_status()
            self._check_content_type(url, resp.headers['content-type'])
            return await resp.text()
        except aiohttp.ClientError as e:
            status_code = getattr(e, 'code', None)
            raise PublicKeyRetrieverException(e, status_code=status_code)
