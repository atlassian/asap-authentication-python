import asyncio
from typing import Dict, Any

import jwt

from atlassian_jwt_auth import key
from atlassian_jwt_auth.verifier import JWTAuthVerifier as _JWTAuthVerifier


class JWTAuthVerifier(_JWTAuthVerifier):
    async def verify_jwt(self, a_jwt: str, audience: str, leeway: int=0, **requests_kwargs: Any) -> Dict[Any, Any]:
        """Verify if the token is correct

        Returns:
             dict: the claims of the given jwt if verification is successful.

        Raises:
            ValueError: if verification failed.
        """
        key_identifier = key._get_key_id_from_jwt_header(a_jwt)

        public_key = self._retrieve_pub_key(key_identifier, requests_kwargs)
        if asyncio.iscoroutine(public_key):
            public_key = await public_key

        alg = jwt.get_unverified_header(a_jwt).get('alg', None)
        public_key_obj = self._load_public_key(public_key, alg)
        return self._decode_jwt(
            a_jwt, key_identifier, public_key_obj,
            audience=audience, leeway=leeway)
