# malpedia

Python client and command-line interface for the [Malpedia REST API](https://malpedia.caad.fkie.fraunhofer.de/usage/api).
It covers every documented endpoint.

Most data is public. A Malpedia account is needed for samples, ApiScout data, YARA scans and rules above TLP:WHITE.

## Installation

Requires Python 3.11 or later.

```bash
uv tool install malpedia    # or: pipx install malpedia
```

To use it as a library, run `uv add malpedia` or `pip install malpedia`.

## Command line

```console
$ malpedia family search emotet
Family               Also known as
js.unidentified_003
win.emotet           Geodo, Heodo

$ malpedia yara get win.emotet -o rules/
$ malpedia yara sync ~/yara-rules     # run again later to fetch only changes
$ malpedia --json actor show apt28 | jq .meta.country
```

Run `malpedia --help`, or `malpedia COMMAND --help`, to see every command and option.

| Command | What it does |
| --- | --- |
| `family list / show / search / bib` | Malware families and their references |
| `actor list / show / search / bib` | Threat actors and their references |
| `sample list / info / download` | Samples, looked up by MD5 or SHA256 |
| `yara list / get / tlp / after / auto / sync / scan` | YARA rules, as text, one file per rule, or ZIP |
| `apiscout list / scan` | ApiVector fingerprints |
| `export bib / misp / references` | Bulk exports of the whole dataset |
| `auth login / logout / status` | Manage the API token |
| `version` | Client version and Malpedia dataset version |

### Authentication

Create an API token in your Malpedia account settings, then run:

```bash
malpedia auth login                            # prompts for the token without echoing it
malpedia auth login --with-token < token.txt   # reads the token from stdin
```

The token is checked and then stored with mode 0600 in `config.json` under the platform's config directory
(for example `~/.config/malpedia/` on Linux).
If the `MALPEDIA_API_TOKEN` environment variable is set, it is used instead of the stored token.

### Output and scripting

- Data goes to stdout. Progress messages, warnings and errors go to stderr.
- `--json` prints compact JSON instead of tables, lists and pretty-printed JSON.
- When stdout is not a terminal, tables become tab-separated lines and lists have one item per line.
- Binary output (`--zip`) is never written to a terminal. Pass `-o FILE` or redirect stdout.
- Large downloads written with `-o FILE` are streamed to disk with a progress bar, and the file only appears once the
  download is complete.
- `-q` hides progress messages. `-v` logs each HTTP request. `--no-color` or `NO_COLOR=1` turns off color.
- Family and actor lists and the MISP and reference exports are cached under the cache directory and reused until
  Malpedia's dataset version changes or you log in or out. `--no-cache` skips reading the cache and refreshes it.
- On a terminal, `family show` and `actor show` print a readable summary. Add `--json` for the full data.
- Exit codes: `0` success, `1` error, `2` invalid usage, `3` missing or rejected credentials, `4` not found,
  `130` interrupted.

> [!WARNING]
> `malpedia sample download` writes **live malware** to disk. Only use it in an isolated analysis environment.
> ZIP archives use the password `infected`.

### Shell completion

```bash
eval "$(malpedia completion bash)"   # in ~/.bashrc
eval "$(malpedia completion zsh)"    # in ~/.zshrc
malpedia completion fish > ~/.config/fish/completions/malpedia.fish
```

Family and actor IDs complete too, from a list cached for a day.

## Library

```python
from malpedia import Client, NotFoundError

with Client("your-api-token") as client:
    family = client.get_family("win.emotet")
    rules = client.get_yara("win.emotet")  # {tlp: {filename: rule}}
    for sample in client.list_samples("win.emotet"):
        print(sample["sha256"], sample["status"])

    with open("tlp_white.zip", "wb") as fh:
        client.download("yara_tlp_zip", fh, argument="white")

    try:
        client.get_actor("no_such_actor")
    except NotFoundError as exc:
        print(exc.status_code, exc.detail)
```

The client also accepts `username=` and `password=` for HTTP Basic authentication. Rate limits (HTTP 429) and
temporary server errors are retried with backoff, honoring `Retry-After`. Return values are annotated with the
TypedDicts in `malpedia.types`, and `Client.download()` streams large exports into a file without loading them into
memory.
Errors derive from `MalpediaError`: `AuthenticationError`, `NotFoundError` and `APIError` for HTTP errors,
and `TransportError` for network failures and timeouts.

## Development

```bash
uv sync
uv run pytest                                     # offline tests
MALPEDIA_API_TOKEN=... uv run pytest -m live      # tests against the real API
uv run ruff check && uv run ruff format --check && uv run ty check
```

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/).
To release, run the Release workflow from the Actions tab with the new version number. It sets the version,
writes the CHANGELOG.md entry, tags the commit, publishes to PyPI with trusted publishing and creates the GitHub
release. Notes written under `## [Unreleased]` in CHANGELOG.md become the entry. If that section is empty, the entry is
generated from the commits since the last release with [git-cliff](https://git-cliff.org/).

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
