"""Provide asyncio support"""
import sys

if sys.version_info >= (3, 5):
    try:
        import aiohttp
        from .auth import JWTAuth
        from .key import HTTPSPublicKeyRetriever
        from .verifier import JWTAuthVerifier
    except ImportError:
        import warnings
        warnings.warn(
            'Could not import aiohttp code as aiohttp is not installed.')


del sys
