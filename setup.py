#!/usr/bin/env python
from setuptools import setup


setup(
    setup_requires=['pbr<=6.0.0', 'pytest-runner'],
    pbr=True,
    platforms=['any'],
    zip_safe=False,
)
