#!/usr/bin/env python
from setuptools import setup


setup(
    setup_requires=['pbr==1.0.1'],
    pbr=True,
    tests_require=['mock', 'nose', ],
    test_suite='nose.collector',
    platforms=['any'],
    zip_safe=False,
)
