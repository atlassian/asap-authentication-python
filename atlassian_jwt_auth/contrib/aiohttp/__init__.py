"""Provide asyncio support"""
import sys

if sys.version_info >= (3, 5):
    try:
        import aiohttp  # noqa
        from .auth import JWTAuth  # noqa
        from .key import HTTPSPublicKeyRetriever  # noqa
        from .verifier import JWTAuthVerifier  # noqa
    except ImportError as e:
        import warnings
        warnings.warn(str(e))


del sys
