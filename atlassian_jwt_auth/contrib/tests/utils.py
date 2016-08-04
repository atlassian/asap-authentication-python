import atlassian_jwt_auth


class StaticPublicKeyRetriever(object):
    """ Retrieves a key from a static list of public keys
    (for use in tests only) """
    def __init__(self, key_dict):
        self.keys = key_dict or {}

    def add_key(self, key_id, value):
        self.keys[key_id] = value

    def retrieve(self, key_identifier, **requests_kwargs):
        return self.keys[key_identifier.key_id]


def static_verifier(keys):
    return atlassian_jwt_auth.JWTAuthVerifier(
        StaticPublicKeyRetriever(keys)
    )
