"""Provide asyncio support"""
import sys

if sys.version_info >= (3, 5):
    try:
        import aiohttp
        from .auth import JWTAuth
        from .key import HTTPSPublicKeyRetriever
        from .verifier import JWTAuthVerifier
    except ImportError as e:
        import warnings
        warnings.warn(str(e))


del sys
