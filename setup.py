#!/usr/bin/env python
from setuptools import setup


setup(
    setup_requires=['pbr', 'pytest'],
    pbr=True,
    platforms=['any'],
    zip_safe=False,
)
