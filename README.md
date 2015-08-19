# Atlassian JWT authentication
This package provides an implementation of the [Service to Service Authentication](https://extranet.atlassian.com/display/I/Service+to+Service+Authentication+-+Specification) specification.

----

## Using this library

### To create a JWT for authentication

```python
    import atlassian_jwt_auth


    signer = atlassian_jwt_auth.create_signer('issuer', 'issuer/key', private_key_pem)
    a_jwt = signer.generate_jwt('audience')
```


### To create a JWT using a file on disk in the conventional location

Each time you call `generate_jwt` this will find the latest active key file (ends with `.pem`) and use it to generate your JWT.

```python
    import atlassian_jwt_auth


    signer = atlassian_jwt_auth.create_signer_from_file_private_key_repository('issuer', '/opt/jwtprivatekeys')
    a_jwt = signer.generate_jwt('audience')
```


### To verify a JWT
```python
    import atlassian_jwt_auth

    public_key_retriever = atlassian_jwt_auth.HTTPSPublicKeyRetriever('https://example.com')
    verifier = atlassian_jwt_auth.JWTAuthVerifier(public_key_retriever)
    verified_claims = verifier.verify_jwt(a_jwt, 'audience')
```

## Installation
To install simply run
```
$ pip install atlassian-jwt-auth
```

### CI builds
This project uses travis ci for builds.
[![Build Status](https://travis-ci.org/atlassian/asap-authentication-python.svg?branch=master)](https://travis-ci.org/atlassian/asap-authentication-python)
