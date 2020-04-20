# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
import malpediaclient


with open('README.md') as f:
    README = f.read()

with open('LICENSE') as f:
    LICENSE = f.read()

setup(
    name='malpediaclient',
    version=malpediaclient.__version__,
    description='Malpedia REST API Client.',
    long_description=README,
    author='Steffen Enders',
    author_email='steffen.enders@tu-dortmund.de',
    url='https://malpedia.caad.fkie.fraunhofer.de',
    license=LICENSE,
    entry_points={
        "console_scripts": ['malpediaclient = malpediaclient.cli:main']
        },
    packages=find_packages(exclude=('tests', 'docs'))
)
