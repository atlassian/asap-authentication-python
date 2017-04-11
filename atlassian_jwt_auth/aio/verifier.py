import asyncio

from atlassian_jwt_auth.verifier import JWTAuthVerifier as _JWTAuthVerifier


class JWTAuthVerifier(_JWTAuthVerifier):
    async def _decode_jwt(self, a_jwt, key_id, jwt_key='', **kwargs):
        """Decode JWT and check if it's valid

        Args:
            a_jwt (bytes): serialized JWT token.
            key_id (str): `kid` parameter of the token.
            jwt_key (str | asyncio.Future): JWT public key or a future that
                provides the key.
        """
        if asyncio.iscoroutine(jwt_key):
            jwt_key = await jwt_key
        return super()._decode_jwt(a_jwt, key_id, jwt_key, **kwargs)
