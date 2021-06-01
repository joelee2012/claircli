#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
from setuptools import setup

requires = [
    'requests',
    'docker',
    'Jinja2',
    'pyyaml',
    'six',
    'colorlog',
]

test_requirements = [
    'responses'
]

here = os.path.abspath(os.path.dirname(__file__))
about = {}
with open(os.path.join(here, 'claircli', '__version__.py')) as f:
    exec(f.read(), about)

with open('README.md') as f:
    readme = f.read()

setup(
    name=about['__title__'],
    version=about['__version__'],
    description=about['__description__'],
    long_description=readme,
    long_description_content_type='text/markdown',
    url=about['__url__'],
    author=about['__author__'],
    author_email=about['__author_email__'],
    packages=['claircli'],
    install_requires=requires,
    tests_require=test_requirements,
    license=about['__license__'],
    package_data={'': ['LICENSE'], 'claircli': ['templates/html-report.j2']},
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*,'
                    ' !=3.3.*, !=3.4.*, !=3.5.*',
    entry_points={
        'console_scripts': [
            'claircli = claircli.cli:main'
        ]
    },
    classifiers=[
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Software Development',
    ],
)
