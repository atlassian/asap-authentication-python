============================
Atlassian JWT authentication
============================

.. image:: https://github.com/atlassian/asap-authentication-python/workflows/Tests/badge.svg
.. image:: https://img.shields.io/pypi/v/atlassian-jwt-auth.svg
   :target: https://pypi.org/project/atlassian-jwt-auth

This package provides an implementation of the `Service to Service Authentication <https://s2sauth.bitbucket.io/spec/>`_ specification.

----

Installation
============

To install simply run

.. code:: sh

    $ pip install atlassian-jwt-auth

Using this library
==================

To create a JWT for authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    import atlassian_jwt_auth


    signer = atlassian_jwt_auth.create_signer('issuer', 'issuer/key', private_key_pem)
    a_jwt = signer.generate_jwt('audience')


To create a JWT using a file on disk in the conventional location
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each time you call ``generate_jwt`` this will find the latest active key file (ends with ``.pem``) and use it to generate your JWT.

.. code:: python

    import atlassian_jwt_auth


    signer = atlassian_jwt_auth.create_signer_from_file_private_key_repository('issuer', '/opt/jwtprivatekeys')
    a_jwt = signer.generate_jwt('audience')

To create a JWT using a data uri
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    import atlassian_jwt_auth
    from atlassian_jwt_auth.key import DataUriPrivateKeyRetriever

    key_id, private_key_pem = DataUriPrivateKeyRetriever('Your base64 encoded data uri').load('issuer')
    signer = atlassian_jwt_auth.create_signer('issuer', 'issuer/key', private_key_pem)
    a_jwt = signer.generate_jwt('audience')



To make an authenticated HTTP request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you use the ``atlassian_jwt_auth.contrib.requests.JWTAuth`` provider, you
can automatically generate JWT tokens when using the ``requests`` library to
perform authenticated HTTP requests.

.. code:: python

    import atlassian_jwt_auth
    from atlassian_jwt_auth.contrib.requests import JWTAuth

    signer = atlassian_jwt_auth.create_signer('issuer', 'issuer/key', private_key_pem)
    response = requests.get(
        'https://your-url',
        auth=JWTAuth(signer, 'audience')
    )

One can also use ``atlassian_jwt_auth.contrib.aiohttp.JWTAuth``
to authenticate ``aiohttp`` requests:

.. code:: python

    import aiohttp

    import atlassian_jwt_auth
    from atlassian_jwt_auth.contrib.aiohttp import JWTAuth

    signer = atlassian_jwt_auth.create_signer('issuer', 'issuer/key', private_key_pem)

    async with aiohttp.ClientSession() as session:
        async with session.get('https://your-url',
                               auth=JWTAuth(signer, 'audience')) as resp:
            ...


If you want to reuse tokens that have the same claim within their period of validity
then pass through `reuse_jwts=True` when calling  `create_signer`.
For example:


.. code:: python

    import atlassian_jwt_auth
    import requests
    from atlassian_jwt_auth.contrib.requests import JWTAuth

    signer = atlassian_jwt_auth.create_signer('issuer', 'issuer/key', private_key_pem, reuse_jwts=True)
    response = requests.get(
        'https://your-url',
        auth=JWTAuth(signer, 'audience')
    )

If you want to generate tokens with a longer lifetime than the default 1 minute period,
you can do so via specifying a `lifetime` value to `create_signer`.
For example:


.. code:: python

    import datetime

    import atlassian_jwt_auth
    import requests
    from atlassian_jwt_auth.contrib.requests import JWTAuth

    signer = atlassian_jwt_auth.create_signer(
        'issuer', 'issuer/key', private_key_pem,
        reuse_jwts=True, lifetime=datetime.timedelta(minutes=2))
    response = requests.get(
        'https://your-url',
        auth=JWTAuth(signer, 'audience')
    )


To verify a JWT
~~~~~~~~~~~~~~~

.. code:: python

    import atlassian_jwt_auth

    public_key_retriever = atlassian_jwt_auth.HTTPSPublicKeyRetriever('https://example.com')
    verifier = atlassian_jwt_auth.JWTAuthVerifier(public_key_retriever)
    verified_claims = verifier.verify_jwt(a_jwt, 'audience')

For Python versions starting from ``Python 3.5``, note this library no longer supports python 3.5, ``atlassian_jwt_auth.contrib.aiohttp``
provides drop-in replacements for the components that
perform HTTP requests, so that they use ``aiohttp`` instead of ``requests``:

.. code:: python

    import atlassian_jwt_auth.contrib.aiohttp

    public_key_retriever = atlassian_jwt_auth.contrib.aiohttp.HTTPSPublicKeyRetriever('https://example.com')
    verifier = atlassian_jwt_auth.contrib.aiohttp.JWTAuthVerifier(public_key_retriever)
    verified_claims = await verifier.verify_jwt(a_jwt, 'audience')
