# Malpedia REST Client

This repository contains a Python interface for the [Malpedia REST API](https://malpedia.caad.fkie.fraunhofer.de).
To use the basic functionalities of this client, no user account on Malpedia is needed.
However, for the analytics and some other extended functionalities, an account and the connected credentials are required.

## Requirements

- Python 3.6 or higher
- `requests` library

## Installation

Since version v0.3.1 `malpediaclient` is available via [PyPI](https://pypi.org/project/malpediaclient/0.3.2/), which simplifies installation to:

```bash
pip install malpediaclient
```


In case you want to install locally from the repository, please use:


```bash
pip install -e .
```

or

```bash
python setup.py install
```

## CLI Usage

Either use `python run.py --help` in this directory or `malpediaclient --help` from anywhere.

## Configuration

You can configure your Malpedia credentials in several ways:

1. Create a JSON configuration file in one of these locations:
   - `./malpedia.json` or `./.malpedia.json` (current directory)
   - `$HOME/.malpedia.json` (user's home directory)
   - `/etc/malpedia.json` (system-wide)
   - `%APPDATA%\malpedia\malpedia.json` (Windows)

   The JSON file should have this structure:
   ```json
   {
     "username": "your_username",
     "password": "your_password"
   }
   ```
   
   Or with an API token:
   ```json
   {
     "apitoken": "your_api_token"
   }
   ```

2. Pass credentials via command line arguments (see `--help` for details)

## Changelog

* 2025-07-25: v0.3.2: Removed dependency issue in setup.py, disabled scan functions, and published to PyPI (THX to [dspruell-rs](https://github.com/dspruell-rs)).
* 2025-03-13: v0.3.0: Updated to Python 3, removed Python 2 compatibility code, improved error handling (THX to [Marc R](https://github.com/seifreed)).
* 2020-08-10: Added support for a JSON config file to enable storing an apitoken or user/password for authentication (THX to [Luca Corbatto](https://github.com/targodan)).
