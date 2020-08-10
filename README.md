# Malpedia REST Client

This repository contains a python interface for the [Malpedia REST Api](https://malpedia.caad.fkie.fraunhofer.de).
To use the basic functionalities of this client, no user account on Malpedia is needed.
However, for the analytics and some other extended functionalities, an account and the connected credentials are required.

## Installation
`python setup.py install`

## CLI Usage
Either use `python run.py --help` in this directory or `malpediaclient --help` from anywhere.

## Changelog

 * 2020-08-10 added support for a JSON config file to enable storing an apitoken or user/password for authentication (THX to [Luca Corbatto](https://github.com/targodan))
