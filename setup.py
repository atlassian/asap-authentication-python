#!/usr/bin/env python
from setuptools import setup, find_packages


setup(
    name='atlassian-jwt-auth',
    packages=find_packages(),
    version='0.0.1',
    install_requires=[
        'cryptography==0.8.2',
        'PyJWT==1.1.0',
        'requests==2.6.0',
    ],
    test_suite='atlassian_jwt_auth.test',
    platforms=['any'],
    license='MIT',
    zip_safe=False,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'License :: OSI Approved :: MIT License',
    ],
)
