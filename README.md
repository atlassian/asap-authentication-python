# Atlassian JWT authentication

[![travis-status-image]][travis]
[![pypi-version-image]][pypi]

This package provides an implementation of the [Service to Service Authentication](http://s2sauth.bitbucket.org/spec/) specification.

----

## Installation
To install simply run
```
$ pip install atlassian-jwt-auth
```

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

### To make an authenticated HTTP request

If you use the `atlassian_jwt_auth.contrib.requests.JWTAuth` provider, you
can automatically generate JWT tokens when using the `requests` library to
perform authenticated HTTP requests.

```python
    import atlassian_jwt_auth
    from atlassian_jwt_auth.contrib.requests import JWTAuth

    signer = atlassian_jwt_auth.create_signer('issuer', 'issuer/key', private_key_pem)
    response = requests.get(
        'https://your-url'
        auth=JWTAuth(signer, 'audience')
    )
```

### To verify a JWT
```python
    import atlassian_jwt_auth

    public_key_retriever = atlassian_jwt_auth.HTTPSPublicKeyRetriever('https://example.com')
    verifier = atlassian_jwt_auth.JWTAuthVerifier(public_key_retriever)
    verified_claims = verifier.verify_jwt(a_jwt, 'audience')
```

[travis-status-image]: https://secure.travis-ci.org/atlassian/asap-authentication-python.svg?branch=master
[travis]: http://travis-ci.org/atlassian/asap-authentication-python?branch=master

[pypi-version-image]: https://img.shields.io/pypi/v/atlassian-jwt-auth.svg
[pypi]: https://pypi.python.org/pypi/atlassian-jwt-auth
