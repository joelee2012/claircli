#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup
from claircli.version import __version__
requires = [
    'requests',
    'docker',
    'Jinja2',
    'pyyaml',
    'six',
    'colorlog',
]

setup(
    name='claircli',
    version=__version__,
    description='Simple command line tool to interact with CoreOS Clair',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/joelee2012/claircli',
    author='Joe Lee',
    author_email='lj_2005@163.com',
    packages=['claircli'],
    license='Apache 2.0',
    package_data={
        'claircli': ['templates/html-report.j2']
    },
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*,'
                    ' !=3.3.*, !=3.4.*, !=3.5.*',
    install_requires=requires,
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
        'Topic :: Software Development',
    ],
)
