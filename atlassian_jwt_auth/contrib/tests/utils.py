import atlassian_jwt_auth


def get_static_retriever_class(keys):

    class StaticPublicKeyRetriever(object):
        """ Retrieves a key from a static list of public keys
        (for use in tests only) """

        def __init__(self, *args, **kwargs):
            self.keys = keys

        def retrieve(self, key_identifier, **requests_kwargs):
            return self.keys[key_identifier.key_id]

    return StaticPublicKeyRetriever


def static_verifier(keys):
    return atlassian_jwt_auth.JWTAuthVerifier(
        get_static_retriever_class(keys)()
    )
