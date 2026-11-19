# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Support for every endpoint in the Malpedia API documentation, including bibliographies, references, sample info,
  MD5 lookups, YARA rules as ZIP archives, YARA-Signator rules, listing all samples and ApiScout scans.
- A new `malpedia` command line with noun-verb commands, `--json` output, an `auth login` command and distinct exit
  codes.
- Typed exceptions, request timeouts, and retries with backoff on rate limits and server errors that honor
  `Retry-After`.
- Typed response models in `malpedia.types`.
- `Client.download()`, which streams large exports to a file without holding them in memory. The command line uses it
  for `-o` and shows a progress bar on a terminal.
- A cache for `family list`, `actor list`, `export misp` and `export references` that stays valid until the Malpedia
  dataset version changes, with a `--no-cache` option to refresh it.
- Readable summaries for `family show` and `actor show` on a terminal.
- `malpedia yara sync DIR`, which keeps a directory of YARA rules up to date.
- Shell completion for bash, zsh and fish, including family and actor IDs, via `malpedia completion`.
- Global options such as `--json` and `-q` work before or after the command.
- Automated releases to PyPI with trusted publishing and build attestations.

### Changed

- **Breaking:** the package, import and command are now `malpedia`, replacing `malpediaclient`.
- **Breaking:** Python 3.11 or later is required, since Python 3.10 has reached end of life.
- **Breaking:** client methods return data instead of writing files, credentials are passed to `Client(...)`, and
  `scan_yara(family_id, rule)` takes the rule text.
- **Breaking:** the old `malpedia.json` config files are no longer read. Run `malpedia auth login` once.

### Removed

- `scan_binary`, whose endpoint does not exist.

### Fixed

- `scan_yara` posted to an endpoint that does not exist.
- The package metadata declared the MIT license instead of Apache-2.0.

## [0.3.2] - 2025-07-25

### Fixed

- Removed a dependency issue in `setup.py`, disabled the scan functions and published to PyPI
  (thanks to [dspruell-rs](https://github.com/dspruell-rs)).

## [0.3.0] - 2025-03-13

### Changed

- Updated to Python 3, removed Python 2 compatibility code and improved error handling
  (thanks to [Marc R](https://github.com/seifreed)).

## [0.2.0] - 2020-08-10

### Added

- A JSON config file for storing an API token or a username and password
  (thanks to [Luca Corbatto](https://github.com/targodan)).
