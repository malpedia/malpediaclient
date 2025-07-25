#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from pathlib import Path

# Read the README.md file
with open('README.md', encoding='utf-8') as f:
    README = f.read()

# Read the LICENSE file
with open('LICENSE', encoding='utf-8') as f:
    LICENSE = f.read()

setup(
    name='malpediaclient',
    version="0.3.2",
    description='Malpedia REST API Client.',
    long_description=README,
    long_description_content_type='text/markdown',
    author='Steffen Enders',
    author_email='steffen.enders@tu-dortmund.de',
    url='https://malpedia.caad.fkie.fraunhofer.de',
    license=LICENSE,
    entry_points={
        "console_scripts": ['malpediaclient = malpediaclient.cli:main']
    },
    packages=find_packages(exclude=('tests', 'docs')),
    install_requires=[
        'requests>=2.31.0',
    ],
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
    ],
)
