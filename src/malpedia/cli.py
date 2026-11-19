"""The `malpedia` command line."""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import io
import json
import logging
import os
import secrets
import sys
import time
from collections.abc import Callable, Generator, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from typing import Any, BinaryIO, NoReturn, ParamSpec, TypeVar

import rich_click as click
from click.shell_completion import CompletionItem, get_completion_class
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
from rich.table import Table
from rich.text import Text

from malpedia import config
from malpedia.client import TLP_LEVELS, Client, __version__, normalize_hash, normalize_tlp
from malpedia.exceptions import (
    APIError,
    AuthenticationError,
    InvalidArgumentError,
    MalpediaError,
    NotFoundError,
    TransportError,
)
from malpedia.types import Actor, Family

EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_AUTH = 3
EXIT_NOT_FOUND = 4
EXIT_INTERRUPTED = 130
CACHE_MAX_AGE = 24 * 60 * 60
CACHE_RETRY_AFTER = 10 * 60
MALPEDIA_URL = "https://malpedia.caad.fkie.fraunhofer.de"
SUMMARY_DESCRIPTION_LENGTH = 200
SUMMARY_SYNONYMS = 10

P = ParamSpec("P")
R = TypeVar("R")
T = TypeVar("T")

click.rich_click.COMMAND_GROUPS = {
    "malpedia": [
        {"name": "Data", "commands": ["family", "actor", "sample", "yara", "apiscout", "export"]},
        {"name": "Setup", "commands": ["auth", "completion", "version"]},
    ]
}


@dataclass
class State:
    """Global options of one invocation, plus helpers that write its output.

    Data goes to stdout and messages to stderr. Output adapts to whether stdout is a
    terminal: tables and highlighted JSON for people, plain lines and compact JSON for
    pipes and files.
    """

    as_json: bool = False
    quiet: bool = False
    no_cache: bool = False
    timeout: float = 60.0
    out: Console = field(default_factory=Console)
    err: Console = field(default_factory=lambda: Console(stderr=True))
    tty: bool = field(default_factory=lambda: sys.stdout is not None and sys.stdout.isatty())
    _client: Client | None = None
    _dataset_version: int | None = None
    _version_checked: bool = False

    @property
    def client(self) -> Client:
        """API client, created on first use with the configured token."""
        if self._client is None:
            token, _ = config.resolve_token()
            self._client = Client(token, timeout=self.timeout)
        return self._client

    def close(self) -> None:
        """Close the API client if one was created."""
        if self._client is not None:
            self._client.close()

    def dataset_version(self) -> int | None:
        """Dataset version of Malpedia, requested once per invocation, or None if the answer is malformed.

        Network errors are raised, since the request the version guards would fail the same way.
        """
        if not self._version_checked:
            self._version_checked = True
            try:
                data = self.client.get_version()
            except TransportError:
                raise
            except MalpediaError:
                data = None
            version = data.get("version") if isinstance(data, dict) else None
            self._dataset_version = version if isinstance(version, int) and not isinstance(version, bool) else None
        return self._dataset_version

    def cached(self, name: str, fetch: Callable[[], T], kind: type[list] | type[dict]) -> T:
        """Return data from the dataset cache, or fetch it and store it.

        An entry is reused while the dataset version and the API token are unchanged. With
        `--no-cache` the entry is not read but is still refreshed. Cache errors are ignored.

        Args:
            name: Endpoint name, used as the file name.
            fetch: Function that loads the data from the API.
            kind: Type of the data, used to reject malformed entries.
        """
        version = self.dataset_version()
        if version is None:
            return fetch()
        path = config.cache_dir() / "data" / f"{name}.json"
        token = config.resolve_token()[0]
        account = hashlib.sha256(token.encode()).hexdigest()[:16] if token else None
        if not self.no_cache:
            with contextlib.suppress(OSError, ValueError, KeyError, TypeError):
                entry = json.loads(path.read_text(encoding="utf-8"))
                if entry["version"] == version and entry["account"] == account and isinstance(entry["data"], kind):
                    return entry["data"]
        data = fetch()
        _write_json_atomic(path, {"version": version, "account": account, "data": data})
        return data

    def info(self, message: str) -> None:
        """Print a progress message to stderr unless `--quiet` is set."""
        if not self.quiet:
            self.err.print(escape(message), highlight=False, soft_wrap=True)

    def emit_json(self, data: Any) -> None:
        """Print data as highlighted JSON on a terminal, or as compact JSON otherwise."""
        if self.tty and not self.as_json:
            self.out.print_json(data=data)
        else:
            click.echo(json.dumps(data, ensure_ascii=False))

    def dumps(self, data: Any) -> str:
        """Serialize data for a file: indented, or compact with `--json`."""
        return json.dumps(data, ensure_ascii=False, indent=None if self.as_json else 2)

    def emit_lines(self, items: Iterable[str]) -> None:
        """Print one item per line, or a JSON array with `--json`."""
        items = list(items)
        if self.as_json:
            self.emit_json(items)
        else:
            for item in items:
                click.echo(item)

    def emit_table(self, rows: Sequence[Mapping[str, Any]], columns: dict[str, str]) -> None:
        """Print rows as a table on a terminal, as tab-separated lines otherwise, or as JSON.

        Args:
            rows: Records to print.
            columns: Keys of `rows` to show, mapped to their column headings.
        """
        if self.as_json:
            self.emit_json(list(rows))
            return

        def cell(value: Any) -> str:
            return ", ".join(map(str, value)) if isinstance(value, list) else str(value)

        if not self.tty:
            for row in rows:
                click.echo("\t".join(cell(row.get(key, "")) for key in columns))
            return
        table = Table(*columns.values(), box=None, pad_edge=False, header_style="bold")
        for row in rows:
            table.add_row(*(escape(cell(row.get(key, ""))) for key in columns))
        self.out.print(table)

    def print_summary(self, panel: Panel) -> None:
        """Print a summary panel followed by a hint about `--json`."""
        self.out.print(panel)
        self.out.print("[dim]Add --json for the full data.[/]")

    def emit_text(self, text: str, output: Path | None) -> None:
        """Write text to `output`, or to stdout if it is None."""
        if output is None:
            click.echo(text, nl=not text.endswith("\n"))
        else:
            output.write_text(text, encoding="utf-8")
            self.info(f"Wrote {output}")

    def _check_binary_stdout(self) -> None:
        if self.tty:
            fail("refusing to write binary data to a terminal", hint="Pass -o FILE or redirect stdout.")

    def download(self, kind: str, output: Path | None, *, argument: str | None = None) -> None:
        """Stream a binary download to `output`, or to stdout if that is not a terminal.

        A regular file is written under a temporary name and renamed when complete, so an
        interrupted download never leaves a truncated file behind. Devices and pipes are
        written directly. A progress bar is shown on stderr when it is a terminal and
        `--quiet` is not set.

        Args:
            kind: Download kind accepted by `Client.download`.
            output: Destination file, or None for stdout.
            argument: TLP level or family ID for the kinds that need one.
        """
        if output is None:
            self._check_binary_stdout()
            self.client.download(kind, sys.stdout.buffer, argument=argument)
            sys.stdout.buffer.flush()
            return
        target = output.resolve() if output.is_symlink() else output
        opener = output.open("wb") if target.exists() and not target.is_file() else _atomic_write(output)
        with opener as fh, self._progress(output.name) as progress:
            size = self.client.download(kind, fh, argument=argument, progress=progress)
        self.info(f"Wrote {output} ({_human_size(size)})")

    @contextlib.contextmanager
    def _progress(self, description: str) -> Generator[Callable[[int, int | None], None] | None]:
        if self.quiet or not self.err.is_terminal:
            yield None
            return
        columns = (
            TextColumn("{task.description}"),
            BarColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
        )
        with Progress(*columns, console=self.err, transient=True) as bar:
            task = bar.add_task(escape(description), total=None)
            yield lambda done, total: bar.update(task, completed=done, total=total)


pass_state = click.make_pass_decorator(State)


def _human_size(size: int) -> str:
    if size < 1024:
        return f"{size} bytes"
    value = size / 1024
    for unit in ("KB", "MB"):
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"


def fail(message: str, *, hint: str | None = None, code: int = EXIT_ERROR) -> NoReturn:
    """Print an error and an optional hint to stderr, then exit.

    Args:
        message: What went wrong.
        hint: How the user can fix it.
        code: Process exit code.
    """
    ctx = click.get_current_context(silent=True)
    err = ctx.obj.err if ctx is not None and isinstance(ctx.obj, State) else Console(stderr=True)
    err.print(f"[bold red]error:[/] {escape(message)}", highlight=False, soft_wrap=True)
    if hint:
        err.print(f"[dim]hint:[/] {escape(hint)}", highlight=False, soft_wrap=True)
    sys.exit(code)


def handle_errors(func: Callable[P, R]) -> Callable[P, R]:
    """Turn client and file errors raised by a command into error messages and exit codes."""

    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return func(*args, **kwargs)
        except (KeyboardInterrupt, click.Abort):
            click.echo(err=True)
            sys.exit(EXIT_INTERRUPTED)
        except AuthenticationError as exc:
            fail(
                exc.detail,
                hint=f"This needs a valid Malpedia account. Run `malpedia auth login` or set {config.TOKEN_ENV}.",
                code=EXIT_AUTH,
            )
        except NotFoundError as exc:
            fail(exc.detail, hint="Check the ID or hash, e.g. with `malpedia family search`.", code=EXIT_NOT_FOUND)
        except APIError as exc:
            fail(f"Malpedia answered HTTP {exc.status_code}: {exc.detail}")
        except TransportError as exc:
            fail(str(exc), hint="Check your network connection, or retry with a larger --timeout.")
        except InvalidArgumentError as exc:
            fail(str(exc), code=EXIT_USAGE)
        except MalpediaError as exc:
            fail(str(exc))
        except OSError as exc:
            fail(f"{exc.strerror or exc}: {exc.filename}" if exc.filename else str(exc))

    return wrapper


output_file = click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    help="Write to FILE instead of stdout.",
)
zip_flag = click.option("--zip", "as_zip", is_flag=True, help="Download as a ZIP archive.")


class TLPLevel(click.ParamType):
    """Click parameter type for a TLP level such as `white` or `tlp_green`."""

    name = "LEVEL"

    def get_metavar(self, param: click.Parameter, ctx: click.Context) -> str:
        """Show the short level names in usage lines."""
        return "{white|green|amber}"

    def shell_complete(self, ctx: click.Context, param: click.Parameter, incomplete: str) -> list[CompletionItem]:
        """Complete the short level names."""
        return [CompletionItem(level) for level in ("white", "green", "amber") if level.startswith(incomplete.lower())]

    def convert(self, value: Any, param: click.Parameter | None, ctx: click.Context | None) -> str:
        """Normalize the level to its API form, such as `tlp_white`."""
        try:
            return normalize_tlp(str(value))
        except ValueError as exc:
            self.fail(str(exc), param, ctx)


class SampleHash(click.ParamType):
    """Click parameter type for an MD5 or SHA256 sample hash."""

    name = "HASH"

    def convert(self, value: Any, param: click.Parameter | None, ctx: click.Context | None) -> str:
        """Validate the hash and return it in lowercase."""
        try:
            return normalize_hash(str(value).strip())
        except ValueError as exc:
            self.fail(str(exc), param, ctx)


def _safe_name(name: str) -> str:
    cleaned = Path(name.replace("\\", "/")).name
    if cleaned in ("", ".", ".."):
        raise MalpediaError(f"refusing unsafe file name from server: {name!r}")
    return cleaned


def _write_rules(state: State, rules: dict[str, dict[str, str]], directory: Path) -> list[str]:
    written: list[str] = []
    for tlp, files in rules.items():
        target = directory / _safe_name(tlp)
        target.mkdir(parents=True, exist_ok=True)
        for filename, rule in files.items():
            path = target / _safe_name(filename)
            path.write_text(rule, encoding="utf-8")
            written.append(str(path))
    if state.as_json:
        state.emit_json(written)
    else:
        for path in written:
            click.echo(path)
    state.info(f"Wrote {len(written)} rule file(s) to {directory}")
    return written


SYNC_STATE_FILE = ".malpedia-sync.json"
SYNC_EPOCH = "2000-01-01"


def _today() -> str:
    return datetime.now(UTC).date().isoformat()


def _read_sync_state(path: Path, *, strict: bool) -> tuple[str, bool]:
    if not path.exists():
        return SYNC_EPOCH, False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        last_sync = datetime.strptime(data["last_sync"], "%Y-%m-%d").date().isoformat()
        return last_sync, data.get("authenticated") is True
    except (ValueError, KeyError, TypeError):
        if strict:
            fail(f"invalid sync state in {path}", hint="Fix or delete the file, or pass --since DATE.")
        return SYNC_EPOCH, False


def _write_sync_state(path: Path, last_sync: str, authenticated: bool) -> None:
    with _atomic_write(path) as fh:
        fh.write(json.dumps({"last_sync": last_sync, "authenticated": authenticated}).encode() + b"\n")


def _emit_rules(state: State, rules: dict[str, dict[str, str]], output: Path | None) -> None:
    if output is not None:
        _write_rules(state, rules, output)
    elif state.as_json:
        state.emit_json(rules)
    else:
        texts = [rule.rstrip("\n") for files in rules.values() for rule in files.values()]
        if texts:
            click.echo("\n\n".join(texts))
        else:
            state.info("No rules.")


def _cached_ids(name: str, fetch: Callable[[Client], list[str]]) -> list[str]:
    """Return IDs from the cache file, refreshing it from the API when older than a day."""
    path = config.cache_dir() / f"{name}.json"
    cached: list[str] = []
    try:
        cached = _string_list(json.loads(path.read_text(encoding="utf-8")))
        if time.time() - path.stat().st_mtime < CACHE_MAX_AGE:
            return cached
    except (OSError, ValueError):
        pass
    try:
        token, _ = config.resolve_token()
        with Client(token, timeout=3.0, retries=0, status_retries=0) as client:
            ids = _string_list(fetch(client))
    except Exception:
        _write_cache(path, cached, age=CACHE_MAX_AGE - CACHE_RETRY_AFTER)
        return cached
    _write_cache(path, ids)
    return ids


@contextlib.contextmanager
def _atomic_write(path: Path) -> Generator[BinaryIO]:
    """Open a temporary file next to `path` and move it over `path` once the block succeeds.

    A symbolic link is followed, so its target is replaced. The file keeps the permissions of
    the file it replaces, and a new file gets the default permissions. Errors name `path`
    rather than the temporary file.
    """
    target = path.resolve() if path.is_symlink() else path
    mode = target.stat().st_mode & 0o777 if target.exists() else None
    partial = target.with_name(f".{target.name}.{secrets.token_hex(4)}.part")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(partial, flags, 0o666)
    except OSError as exc:
        raise OSError(exc.errno, exc.strerror, str(path)) from exc
    try:
        with os.fdopen(fd, "wb") as fh:
            yield fh
        if mode is not None:
            partial.chmod(mode)
        partial.replace(target)
    except OSError as exc:
        if exc.filename == str(partial):
            raise OSError(exc.errno, exc.strerror, str(path)) from exc
        raise
    finally:
        partial.unlink(missing_ok=True)


def _write_json_atomic(path: Path, payload: Any) -> None:
    with contextlib.suppress(OSError, ValueError, TypeError):
        path.parent.mkdir(parents=True, exist_ok=True)
        with _atomic_write(path) as fh:
            fh.write(json.dumps(payload, ensure_ascii=False).encode())


def _string_list(data: Any) -> list[str]:
    return [item for item in data if isinstance(item, str)] if isinstance(data, list) else []


def _write_cache(path: Path, ids: list[str], *, age: float = 0) -> None:
    with contextlib.suppress(OSError):
        path.parent.mkdir(parents=True, exist_ok=True)
        with _atomic_write(path) as fh:
            fh.write(json.dumps(ids).encode())
        if age:
            mtime = time.time() - age
            os.utime(path, (mtime, mtime))


def complete_family_id(ctx: click.Context, param: click.Parameter, incomplete: str) -> list[CompletionItem]:
    """Complete a family ID from the cached family list.

    Args:
        ctx: Click context.
        param: The parameter being completed.
        incomplete: The text typed so far.

    Returns:
        Matching family IDs, or an empty list if none can be loaded.
    """
    ids = _cached_ids("families", lambda client: client.list_families())
    return [CompletionItem(i) for i in ids if i.startswith(incomplete)]


def complete_actor_id(ctx: click.Context, param: click.Parameter, incomplete: str) -> list[CompletionItem]:
    """Complete an actor ID from the cached actor list.

    Args:
        ctx: Click context.
        param: The parameter being completed.
        incomplete: The text typed so far.

    Returns:
        Matching actor IDs, or an empty list if none can be loaded.
    """
    ids = _cached_ids("actors", lambda client: client.list_actors())
    return [CompletionItem(i) for i in ids if i.startswith(incomplete)]


def _clip(value: Any) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= SUMMARY_DESCRIPTION_LENGTH else text[:SUMMARY_DESCRIPTION_LENGTH] + "..."


def _joined(value: Any) -> str:
    return ", ".join(map(str, value)) if isinstance(value, list) else str(value or "")


def _count(value: Any) -> int:
    return len(value) if isinstance(value, list | dict) else int(bool(value))


def _summary_panel(title: str, rows: list[tuple[str, str]], url: str) -> Panel:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold")
    grid.add_column()
    for label, value in [*rows, ("URL", url)]:
        grid.add_row(label, Text(value or "-"))
    return Panel(grid, title=Text(title, style="bold"), title_align="left", expand=False)


def _family_summary(family_id: str, data: Family) -> Panel:
    rows = [
        ("ID", family_id),
        ("Name", str(data.get("common_name") or "")),
        ("Also known as", _joined(data.get("alt_names"))),
        ("Attribution", _joined(data.get("attribution"))),
        ("Description", _clip(data.get("description"))),
        ("URLs", str(_count(data.get("urls")))),
        ("Updated", str(data.get("updated") or "")),
    ]
    return _summary_panel(family_id, rows, f"{MALPEDIA_URL}/details/{family_id}")


def _actor_summary(actor_id: str, data: Actor) -> Panel:
    meta = data.get("meta") or {}
    synonyms = meta.get("synonyms") or []
    shown = ", ".join(map(str, synonyms[:SUMMARY_SYNONYMS]))
    if len(synonyms) > SUMMARY_SYNONYMS:
        shown += f", +{len(synonyms) - SUMMARY_SYNONYMS} more"
    rows = [
        ("Name", str(data.get("value") or actor_id)),
        ("Country", _joined(meta.get("country"))),
        ("Synonyms", shown),
        ("References", str(_count(meta.get("refs")))),
        ("Description", _clip(data.get("description"))),
        ("Families", str(_count(data.get("families")))),
    ]
    return _summary_panel(str(data.get("value") or actor_id), rows, f"{MALPEDIA_URL}/actor/{actor_id}")


def _enable_request_logging() -> None:
    logging.basicConfig(format="%(name)s: %(message)s", stream=sys.stderr)
    logging.getLogger("httpx").setLevel(logging.INFO)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", prog_name="malpedia")
@click.option("--json", "as_json", is_flag=True, help="Print machine-readable JSON.")
@click.option("-q", "--quiet", is_flag=True, help="Suppress informational messages.")
@click.option("-v", "--verbose", is_flag=True, help="Log HTTP requests to stderr.")
@click.option("--no-color", is_flag=True, help="Disable colored output (also honors NO_COLOR).")
@click.option(
    "--no-cache",
    is_flag=True,
    help="Do not reuse cached family lists, actor lists and exports, and refresh them instead.",
)
@click.option(
    "--timeout",
    type=click.FloatRange(min=0, min_open=True),
    default=60.0,
    show_default=True,
    help="Network timeout in seconds.",
)
@click.pass_context
def cli(
    ctx: click.Context, as_json: bool, quiet: bool, verbose: bool, no_color: bool, no_cache: bool, timeout: float
) -> None:
    """Query malware families, actors, samples and YARA rules on Malpedia.

    Most data is public. Run `malpedia auth login` or set MALPEDIA_API_TOKEN to access
    samples, ApiScout data and non-public TLP levels.
    """
    if isinstance(sys.stdout, io.TextIOWrapper) and not sys.stdout.isatty():
        sys.stdout.reconfigure(encoding="utf-8")
    if verbose:
        _enable_request_logging()
    ctx.obj = State(
        as_json=as_json,
        quiet=quiet,
        no_cache=no_cache,
        timeout=timeout,
        out=Console(no_color=no_color),
        err=Console(stderr=True, no_color=no_color),
    )
    ctx.call_on_close(ctx.obj.close)


@cli.command()
@pass_state
@handle_errors
def version(state: State) -> None:
    """Show the client version and the current Malpedia dataset version."""
    data = state.client.get_version()
    if state.as_json:
        state.emit_json({"client": __version__, "dataset": data})
    else:
        click.echo(f"malpedia {__version__}")
        click.echo(f"dataset  {data.get('version')} ({data.get('date')})")


@cli.command()
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
def completion(shell: str) -> None:
    """Print the tab-completion script for SHELL.

    Family and actor IDs complete too, from a list cached for a day. Add one of these
    to your shell setup:

    bash: eval "$(malpedia completion bash)" in ~/.bashrc

    zsh: eval "$(malpedia completion zsh)" in ~/.zshrc

    fish: malpedia completion fish > ~/.config/fish/completions/malpedia.fish
    """
    shell_class = get_completion_class(shell)
    assert shell_class is not None
    click.echo(shell_class(cli, {}, "malpedia", "_MALPEDIA_COMPLETE").source())


@cli.group()
def auth() -> None:
    """Manage the API token used for authentication."""


@auth.command()
@click.option("--with-token", is_flag=True, help="Read the token from stdin instead of prompting.")
@pass_state
@handle_errors
def login(state: State, with_token: bool) -> None:
    """Validate an API token and store it in the config file.

    Create tokens in your Malpedia account settings.
    """
    if with_token:
        token = sys.stdin.readline().strip()
    elif sys.stdin.isatty():
        token = click.prompt("API token", hide_input=True).strip()
    else:
        fail("no terminal to prompt for a token", hint="Pipe it in with `malpedia auth login --with-token`.")
    if not token:
        fail("empty token")
    with Client(token, timeout=state.timeout) as client:
        try:
            client.check_apikey()
        except AuthenticationError as exc:
            fail(f"token rejected: {exc.detail}", code=EXIT_AUTH)
    path = config.save_token(token)
    state.info(f"Token is valid and was saved to {path}")


@auth.command()
@pass_state
@handle_errors
def logout(state: State) -> None:
    """Remove the stored API token."""
    if config.delete_token():
        state.info(f"Removed {config.config_path()}")
    else:
        state.info("No stored token.")
    if os.environ.get(config.TOKEN_ENV):
        state.info(f"{config.TOKEN_ENV} is still set and will keep being used.")


@auth.command()
@pass_state
@handle_errors
def status(state: State) -> None:
    """Show where the token comes from and whether it is valid."""
    token, source = config.resolve_token()
    if token is None:
        fail(
            "not logged in; only public data is available",
            hint=f"Run `malpedia auth login` or set {config.TOKEN_ENV}.",
            code=EXIT_AUTH,
        )
    detail = state.client.check_apikey().get("detail", "Valid token.")
    if state.as_json:
        state.emit_json({"source": source, "detail": detail})
    else:
        click.echo(f"{detail} (from {source})")


@cli.group()
def family() -> None:
    """Malware families."""


@family.command("list")
@click.option("--details", is_flag=True, help="Include all metadata (large).")
@pass_state
@handle_errors
def family_list(state: State, details: bool) -> None:
    """List all family IDs."""
    if details:
        state.emit_json(state.cached("get-families", state.client.get_families, dict))
    else:
        state.emit_lines(state.cached("list-families", state.client.list_families, list))


@family.command("show")
@click.argument("family_id", shell_complete=complete_family_id)
@pass_state
@handle_errors
def family_show(state: State, family_id: str) -> None:
    """Show the metadata of a family, e.g. win.emotet."""
    data = state.client.get_family(family_id)
    if state.tty and not state.as_json:
        state.print_summary(_family_summary(family_id, data))
    else:
        state.emit_json(data)


@family.command("search")
@click.argument("needle")
@pass_state
@handle_errors
def family_search(state: State, needle: str) -> None:
    """Find families whose name or synonyms contain NEEDLE."""
    state.emit_table(state.client.find_family(needle), {"name": "Family", "alt_names": "Also known as"})


@family.command("bib")
@click.argument("family_id", shell_complete=complete_family_id)
@output_file
@pass_state
@handle_errors
def family_bib(state: State, family_id: str, output: Path | None) -> None:
    """Print the BibTeX references of a family."""
    state.emit_text(state.client.get_bib_family(family_id), output)


@cli.group()
def actor() -> None:
    """Threat actors."""


@actor.command("list")
@click.option("--details", is_flag=True, help="Include all metadata (large).")
@pass_state
@handle_errors
def actor_list(state: State, details: bool) -> None:
    """List all actor IDs."""
    if details:
        state.emit_json(state.cached("get-actors", state.client.get_actors, dict))
    else:
        state.emit_lines(state.cached("list-actors", state.client.list_actors, list))


@actor.command("show")
@click.argument("actor_id", shell_complete=complete_actor_id)
@pass_state
@handle_errors
def actor_show(state: State, actor_id: str) -> None:
    """Show the metadata of an actor, e.g. apt28."""
    data = state.client.get_actor(actor_id)
    if state.tty and not state.as_json:
        state.print_summary(_actor_summary(actor_id, data))
    else:
        state.emit_json(data)


@actor.command("search")
@click.argument("needle")
@pass_state
@handle_errors
def actor_search(state: State, needle: str) -> None:
    """Find actors whose name or synonyms contain NEEDLE."""
    state.emit_table(
        state.client.find_actor(needle),
        {"name": "Actor", "common_name": "Common name", "synonyms": "Synonyms"},
    )


@actor.command("bib")
@click.argument("actor_id", shell_complete=complete_actor_id)
@output_file
@pass_state
@handle_errors
def actor_bib(state: State, actor_id: str, output: Path | None) -> None:
    """Print the BibTeX references of an actor."""
    state.emit_text(state.client.get_bib_actor(actor_id), output)


@cli.group()
def sample() -> None:
    """Malware samples (requires login)."""


@sample.command("list")
@click.argument("family_id", shell_complete=complete_family_id, required=False)
@pass_state
@handle_errors
def sample_list(state: State, family_id: str | None) -> None:
    """List the samples of FAMILY_ID, or of all families."""
    samples = state.client.list_samples(family_id)
    if isinstance(samples, list):
        state.emit_table(samples, {"sha256": "SHA256", "status": "Status", "version": "Version"})
    else:
        state.emit_json(samples)


@sample.command("info")
@click.argument("sample_hash", metavar="HASH", type=SampleHash())
@pass_state
@handle_errors
def sample_info(state: State, sample_hash: str) -> None:
    """Show the status of a sample by MD5 or SHA256."""
    state.emit_json(state.client.get_sample_info(sample_hash))


@sample.command("download")
@click.argument("sample_hash", metavar="HASH", type=SampleHash())
@click.option(
    "-o",
    "--output-dir",
    type=click.Path(file_okay=False, writable=True, path_type=Path),
    default=Path(),
    help="Directory to save into.  [default: current directory]",
)
@click.option("--zip", "as_zip", is_flag=True, help="Save one ZIP archive with password 'infected'.")
@pass_state
@handle_errors
def sample_download(state: State, sample_hash: str, output_dir: Path, as_zip: bool) -> None:
    """Download a sample and its unpacked or dumped files.

    Saved files are live malware: handle them in an isolated environment. Prints the
    path of each file written.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    if as_zip:
        files = {f"{sample_hash}.zip": state.client.get_sample_zip(sample_hash)}
    else:
        raw = state.client.get_sample_raw(sample_hash)
        files = {f"{sample_hash}_{_safe_name(kind)}": data for kind, data in raw.items()}
    for name, data in files.items():
        path = output_dir / name
        path.write_bytes(data)
        click.echo(path)
    state.info(f"Saved {len(files)} file(s). These are live malware.")


@cli.group()
def yara() -> None:
    """YARA rules."""


@yara.command("list")
@pass_state
@handle_errors
def yara_list(state: State) -> None:
    """List the rule files available to you, per family."""
    rules = state.client.list_yara()
    if state.as_json:
        state.emit_json(rules)
        return
    rows = [{"family": fam, **entry} for fam, entries in rules.items() for entry in entries]
    state.emit_table(rows, {"family": "Family", "tlp": "TLP", "path": "Path"})


@yara.command("get")
@click.argument("family_id", shell_complete=complete_family_id)
@zip_flag
@click.option(
    "-o",
    "--output",
    type=click.Path(writable=True, path_type=Path),
    help="With --zip, the archive file; otherwise a directory to write one file per rule into.",
)
@pass_state
@handle_errors
def yara_get(state: State, family_id: str, as_zip: bool, output: Path | None) -> None:
    """Print the YARA rules of a family."""
    if as_zip:
        state.download("yara_family_zip", output, argument=family_id)
    else:
        _emit_rules(state, state.client.get_yara(family_id), output)


@yara.command("tlp")
@click.argument("level", type=TLPLevel())
@zip_flag
@output_file
@pass_state
@handle_errors
def yara_tlp(state: State, level: str, as_zip: bool, output: Path | None) -> None:
    """Print all YARA rules of one TLP LEVEL."""
    if as_zip:
        state.download("yara_tlp_zip", output, argument=level)
    elif output is not None:
        state.download("yara_tlp", output, argument=level)
    else:
        state.emit_text(state.client.get_yara_tlp(level), None)


@yara.command("after")
@click.argument("date", type=click.DateTime(["%Y-%m-%d"]), metavar="DATE")
@click.option(
    "-o",
    "--output-dir",
    type=click.Path(file_okay=False, writable=True, path_type=Path),
    help="Write one file per rule into this directory.",
)
@pass_state
@handle_errors
def yara_after(state: State, date: datetime, output_dir: Path | None) -> None:
    """Print the YARA rules changed after DATE (YYYY-MM-DD)."""
    _emit_rules(state, state.client.get_yara_after(date.date()), output_dir)


@yara.command("sync")
@click.argument("directory", metavar="DIR", type=click.Path(file_okay=False, writable=True, path_type=Path))
@click.option("--since", type=click.DateTime(["%Y-%m-%d"]), metavar="DATE", help="Fetch rules changed after DATE.")
@pass_state
@handle_errors
def yara_sync(state: State, directory: Path, since: datetime | None) -> None:
    """Download new and changed YARA rules into DIR, one file per rule.

    The date of the last sync is remembered in DIR/.malpedia-sync.json, so the command suits cron.
    After logging in, the next sync fetches everything again to pick up non-public rules. A rule
    that moved to another TLP level is moved here too, but rules deleted on Malpedia stay in DIR:
    remove DIR to start over.
    """
    mark = (dt.date.fromisoformat(_today()) - dt.timedelta(days=1)).isoformat()
    authenticated = config.resolve_token()[0] is not None
    state_file = directory / SYNC_STATE_FILE
    start, had_full_authenticated_sync = _read_sync_state(state_file, strict=since is None)
    if since:
        start = since.date().isoformat()
    elif authenticated and not had_full_authenticated_sync:
        start = SYNC_EPOCH
    rules = state.client.get_yara_after(start)
    directory.mkdir(parents=True, exist_ok=True)
    for tlp, files in rules.items():
        for other in TLP_LEVELS:
            if other != tlp:
                for filename in files:
                    (directory / other / _safe_name(filename)).unlink(missing_ok=True)
    _write_rules(state, rules, directory)
    _write_sync_state(state_file, mark, had_full_authenticated_sync or (authenticated and start == SYNC_EPOCH))


@yara.command("auto")
@zip_flag
@output_file
@pass_state
@handle_errors
def yara_auto(state: State, as_zip: bool, output: Path | None) -> None:
    """Print all rules generated by YARA-Signator."""
    if as_zip:
        state.download("yara_auto_zip", output)
    elif output is not None:
        state.download("yara_auto", output)
    else:
        state.emit_text(state.client.get_yara_auto(), None)


@yara.command("scan")
@click.argument("family_id", shell_complete=complete_family_id)
@click.argument("rule_file", type=click.File("rb"))
@pass_state
@handle_errors
def yara_scan(state: State, family_id: str, rule_file: BinaryIO) -> None:
    """Scan the samples of a family with the rule in RULE_FILE ('-' for stdin)."""
    result = state.client.scan_yara(family_id, rule_file.read())
    detail = str(result.get("detail", ""))
    if detail != "Scan complete.":
        fail(detail or json.dumps(result), hint="Check the rule with `yara RULE_FILE /dev/null`.")
    if state.as_json:
        state.emit_json(result)
    else:
        click.echo(detail)


@cli.group()
def apiscout() -> None:
    """ApiScout ApiVector fingerprints."""


@apiscout.command("list")
@click.option("--csv", "as_csv", is_flag=True, help="Print ApiScout-compatible CSV.")
@output_file
@pass_state
@handle_errors
def apiscout_list(state: State, as_csv: bool, output: Path | None) -> None:
    """List all non-zero ApiVector fingerprints (requires login)."""
    if as_csv and output is not None:
        state.download("apiscout_csv", output)
    elif as_csv:
        state.emit_text(state.client.list_apiscout_csv(), None)
    elif output is not None:
        state.emit_text(state.dumps(state.client.list_apiscout()), output)
    else:
        state.emit_json(state.client.list_apiscout())


@apiscout.command("scan")
@click.argument("apivector")
@pass_state
@handle_errors
def apiscout_scan(state: State, apivector: str) -> None:
    """Match a compressed APIVECTOR against Malpedia's fingerprints."""
    state.emit_json(state.client.scan_apiscout(apivector))


@cli.group()
def export() -> None:
    """Bulk exports of the whole dataset."""


@export.command("bib")
@output_file
@pass_state
@handle_errors
def export_bib(state: State, output: Path | None) -> None:
    """BibTeX of all references."""
    if output is not None:
        state.download("bib", output)
    else:
        state.emit_text(state.client.get_bib(), None)


@export.command("misp")
@output_file
@pass_state
@handle_errors
def export_misp(state: State, output: Path | None) -> None:
    """Malpedia as a MISP galaxy cluster (JSON)."""
    state.emit_text(state.dumps(state.cached("get-misp", state.client.get_misp, dict)), output)


@export.command("references")
@output_file
@pass_state
@handle_errors
def export_references(state: State, output: Path | None) -> None:
    """All references with their families and actors (JSON)."""
    state.emit_text(state.dumps(state.cached("get-references", state.client.get_references, dict)), output)


def _set_global(ctx: click.Context, param: click.Parameter, value: Any) -> None:
    if value is None or value is False:
        return
    state = ctx.find_object(State)
    if state is None:
        return
    if param.name == "as_json":
        state.as_json = True
    elif param.name == "quiet":
        state.quiet = True
    elif param.name == "verbose":
        _enable_request_logging()
    elif param.name == "no_color":
        state.out.no_color = state.err.no_color = True
    elif param.name == "no_cache":
        state.no_cache = True
    elif param.name == "timeout":
        state.timeout = value


def _global_options() -> list[click.Option]:
    common: dict[str, Any] = {"expose_value": False, "hidden": True, "callback": _set_global}
    return [
        click.Option(["--json", "as_json"], is_flag=True, **common),
        click.Option(["-q", "--quiet"], is_flag=True, **common),
        click.Option(["-v", "--verbose"], is_flag=True, **common),
        click.Option(["--no-color"], is_flag=True, **common),
        click.Option(["--no-cache"], is_flag=True, **common),
        click.Option(["--timeout"], type=click.FloatRange(min=0, min_open=True), **common),
    ]


def _accept_global_options(command: click.Command) -> None:
    """Let the global options also follow the subcommand, as in `malpedia family list --json`."""
    command.params.extend(_global_options())
    if isinstance(command, click.Group):
        for subcommand in command.commands.values():
            _accept_global_options(subcommand)


for _command in cli.commands.values():
    _accept_global_options(_command)


def main() -> None:
    """Run the command line."""
    cli.main(prog_name="malpedia")
