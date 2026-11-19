"""Storage and lookup of the API token used by the command line."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click

TOKEN_ENV = "MALPEDIA_API_TOKEN"


def config_path() -> Path:
    """Path of the config file in the platform's user config directory."""
    return Path(click.get_app_dir("malpedia")) / "config.json"


def cache_dir() -> Path:
    r"""Return the directory for cached data such as completion candidates.

    This is `$XDG_CACHE_HOME/malpedia` if that variable is an absolute path, else `%LOCALAPPDATA%\malpedia\Cache` on
    Windows and `~/.cache/malpedia` elsewhere.

    Returns:
        Path of the cache directory, which may not exist yet.
    """
    xdg = os.environ.get("XDG_CACHE_HOME", "")
    if xdg and Path(xdg).is_absolute():
        return Path(xdg) / "malpedia"
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "malpedia" / "Cache"
    return Path.home() / ".cache" / "malpedia"


def stored_token() -> str | None:
    """Return the token from the config file, or None if there is none.

    Raises:
        click.ClickException: If the config file exists but cannot be read or parsed.
    """
    path = config_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise click.ClickException(f"cannot read config file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise click.ClickException(f"config file {path} must contain a JSON object")
    token = data.get("apitoken")
    return token if isinstance(token, str) and token else None


def resolve_token() -> tuple[str | None, str | None]:
    """Return the API token and where it came from.

    The `MALPEDIA_API_TOKEN` environment variable takes precedence over the config file.

    Returns:
        The token and a description of its source, or `(None, None)` if there is no token.
    """
    if token := os.environ.get(TOKEN_ENV, "").strip():
        return token, f"environment variable {TOKEN_ENV}"
    if token := stored_token():
        return token, f"config file {config_path()}"
    return None, None


def save_token(token: str) -> Path:
    """Write the token to the config file, readable only by the current user.

    Args:
        token: The API token to store.

    Returns:
        Path of the config file.
    """
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"apitoken": token}, fh, indent=2)
        fh.write("\n")
    tmp.replace(path)
    return path


def delete_token() -> bool:
    """Delete the config file.

    Returns:
        True if a file was deleted, False if there was none.
    """
    try:
        config_path().unlink()
    except FileNotFoundError:
        return False
    return True
