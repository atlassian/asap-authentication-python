#!/usr/bin/env python
from setuptools import setup


setup(
    setup_requires=['pbr<=6.0.0', 'nose'],
    pbr=True,
    test_suite='nose.collector',
    platforms=['any'],
    zip_safe=False,
)
