"""HTTP client for the Malpedia REST API."""

from __future__ import annotations

import base64
import binascii
import contextlib
import datetime as dt
import re
import time
from collections.abc import Callable
from importlib.metadata import PackageNotFoundError, version
from types import TracebackType
from typing import Any, BinaryIO, Literal, Self
from urllib.parse import quote

import httpx

from malpedia.exceptions import (
    APIError,
    AuthenticationError,
    InvalidArgumentError,
    NotFoundError,
    ResponseError,
    TransportError,
)
from malpedia.types import (
    Actor,
    ActorMatch,
    Family,
    FamilyMatch,
    Sample,
    SampleInfo,
    Version,
    YaraFile,
    YaraRules,
)

try:
    __version__ = version("malpedia")
except PackageNotFoundError:
    __version__ = "0+unknown"

DEFAULT_BASE_URL = "https://malpedia.caad.fkie.fraunhofer.de/api/"
DEFAULT_TIMEOUT = httpx.Timeout(60.0, connect=10.0)

TLP = Literal["tlp_white", "tlp_green", "tlp_amber"]
TLP_LEVELS: tuple[TLP, ...] = ("tlp_white", "tlp_green", "tlp_amber")

_HASH_RE = re.compile(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{64}")
_SECONDS_RE = re.compile(r"[0-9]+")

RETRY_STATUSES = frozenset({429, 502, 503, 504})
MAX_RETRY_AFTER = 60.0
MAX_BACKOFF = 30.0
CHUNK_SIZE = 65536


def _segment(value: str) -> str:
    if value in ("", ".", ".."):
        raise InvalidArgumentError(f"invalid path parameter: {value!r}")
    return quote(value, safe="")


def normalize_hash(value: str) -> str:
    """Validate a sample hash and return it in lowercase.

    Args:
        value: An MD5 or SHA256 hash in hex.

    Returns:
        The hash in lowercase.

    Raises:
        InvalidArgumentError: If `value` is not an MD5 or SHA256 hash.
    """
    if not _HASH_RE.fullmatch(value):
        raise InvalidArgumentError(f"not an MD5 or SHA256 hash: {value!r}")
    return value.lower()


def normalize_tlp(value: str) -> TLP:
    """Turn a TLP level such as `white`, `TLP:GREEN` or `tlp_amber` into its API form.

    Args:
        value: The TLP level, with or without a `tlp_` or `TLP:` prefix.

    Returns:
        One of `tlp_white`, `tlp_green` or `tlp_amber`.

    Raises:
        InvalidArgumentError: If `value` is not a supported TLP level.
    """
    normalized = value.lower().replace(":", "_")
    if not normalized.startswith("tlp_"):
        normalized = f"tlp_{normalized}"
    for level in TLP_LEVELS:
        if level == normalized:
            return level
    raise InvalidArgumentError(f"TLP must be one of {', '.join(TLP_LEVELS)}, got {value!r}")


def _date(value: dt.date | str) -> str:
    if isinstance(value, dt.date):
        return value.strftime("%Y-%m-%d")
    try:
        return dt.date.fromisoformat(value).strftime("%Y-%m-%d")
    except ValueError:
        raise InvalidArgumentError(f"date must be YYYY-MM-DD, got {value!r}") from None


class Client:
    """Client for the Malpedia REST API.

    Most endpoints work anonymously. Authenticate with an API token (preferred) or a
    username and password to access registered-only data and non-public TLP levels.
    Use the client as a context manager, or call `close()` when done.

    Every method raises `AuthenticationError`, `NotFoundError` or `APIError` when the API
    answers with an error, `ResponseError` when the answer cannot be interpreted,
    `TransportError` when the API cannot be reached, and `InvalidArgumentError` for
    arguments that are rejected before any request is made.

    Args:
        apitoken: API token from the Malpedia account settings.
        username: Account name for HTTP Basic authentication. Requires `password`.
        password: Account password for HTTP Basic authentication. Requires `username`.
        base_url: Root URL of the API.
        timeout: Timeout in seconds, or an `httpx.Timeout` for finer control.
        retries: Number of retries for failed connection attempts.
        status_retries: Number of retries for GET requests answered with status 429, 502, 503
            or 504. The wait honors a `Retry-After` header in seconds, giving up if it asks for
            more than 60, and otherwise grows exponentially from 1 second (at most 30).
        sleep: Function that waits for a number of seconds between retries.
        transport: Custom httpx transport, for example `httpx.MockTransport` in tests.

    Raises:
        InvalidArgumentError: If both a token and a username and password are given, or
            only one of username and password.
    """

    def __init__(
        self,
        apitoken: str | None = None,
        *,
        username: str | None = None,
        password: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float | httpx.Timeout = DEFAULT_TIMEOUT,
        retries: int = 2,
        status_retries: int = 3,
        sleep: Callable[[float], None] = time.sleep,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if apitoken and (username or password):
            raise InvalidArgumentError("pass either an API token or a username and password, not both")
        if bool(username) != bool(password):
            raise InvalidArgumentError("username and password must be given together")

        self._status_retries = status_retries
        self._sleep = sleep
        headers = {"User-Agent": f"malpedia/{__version__}"}
        if apitoken:
            headers["Authorization"] = f"apitoken {apitoken}"
        self._http = httpx.Client(
            base_url=base_url if base_url.endswith("/") else f"{base_url}/",
            headers=headers,
            auth=httpx.BasicAuth(username, password) if username and password else None,
            timeout=timeout,
            transport=transport or httpx.HTTPTransport(retries=retries),
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP connections."""
        self._http.close()

    def _retry_delay(self, response: httpx.Response, attempt: int) -> float | None:
        if response.request.method != "GET" or response.status_code not in RETRY_STATUSES:
            return None
        if attempt >= self._status_retries:
            return None
        retry_after = response.headers.get("retry-after", "").strip()
        if _SECONDS_RE.fullmatch(retry_after):
            delay = float(retry_after)
            return delay if delay <= MAX_RETRY_AFTER else None
        return min(float(2**attempt), MAX_BACKOFF)

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        detail = response.reason_phrase or "request failed"
        if response.headers.get("content-type", "").startswith("application/json"):
            try:
                body = response.json()
            except ValueError:
                body = None
            if isinstance(body, dict) and isinstance(body.get("detail"), str):
                detail = body["detail"]
        url = str(response.request.url)
        if response.status_code in (401, 403):
            raise AuthenticationError(response.status_code, detail, url)
        if response.status_code == 404:
            raise NotFoundError(response.status_code, detail, url)
        raise APIError(response.status_code, detail, url)

    def _request(self, method: str, path: str, *, content: bytes | None = None) -> httpx.Response:
        attempt = 0
        while True:
            try:
                response = self._http.request(method, path, content=content)
            except httpx.TimeoutException as exc:
                raise TransportError(f"request to {exc.request.url} timed out") from exc
            except httpx.HTTPError as exc:
                raise TransportError(str(exc) or type(exc).__name__) from exc
            if response.is_success:
                return response
            delay = self._retry_delay(response, attempt)
            if delay is None:
                self._raise_for_status(response)
            else:
                self._sleep(delay)
                attempt += 1

    def _stream(self, path: str, destination: BinaryIO, progress: Callable[[int, int | None], None] | None) -> int:
        attempt = 0
        while True:
            try:
                with self._http.stream("GET", path) as response:
                    if response.is_success:
                        return self._copy(response, destination, progress)
                    response.read()
                    delay = self._retry_delay(response, attempt)
                    if delay is None:
                        self._raise_for_status(response)
            except httpx.TimeoutException as exc:
                raise TransportError(f"request to {exc.request.url} timed out") from exc
            except httpx.HTTPError as exc:
                raise TransportError(str(exc) or type(exc).__name__) from exc
            if delay is not None:
                self._sleep(delay)
            attempt += 1

    @staticmethod
    def _copy(
        response: httpx.Response, destination: BinaryIO, progress: Callable[[int, int | None], None] | None
    ) -> int:
        total = None
        if response.headers.get("content-encoding", "identity") == "identity":
            with contextlib.suppress(KeyError, ValueError):
                total = int(response.headers["content-length"])
        written = 0
        for chunk in response.iter_bytes(CHUNK_SIZE):
            destination.write(chunk)
            written += len(chunk)
            if progress is not None:
                progress(written, total)
        return written

    def _json(self, path: str, *, content: bytes | None = None) -> Any:
        response = self._request("POST" if content is not None else "GET", path, content=content)
        try:
            return response.json()
        except ValueError:
            raise ResponseError(f"expected JSON from {response.request.url}") from None

    def _decode(self, path: str, data: Any, key: str | None = None) -> bytes:
        try:
            return base64.b64decode(data[key] if key else data, validate=True)
        except (KeyError, TypeError, binascii.Error):
            raise ResponseError(f"unexpected content from {self._http.base_url}{path}") from None

    def _text(self, path: str) -> str:
        return self._request("GET", path).text

    def _bytes(self, path: str) -> bytes:
        return self._request("GET", path).content

    def download(
        self,
        kind: str,
        destination: BinaryIO,
        *,
        argument: str | None = None,
        progress: Callable[[int, int | None], None] | None = None,
    ) -> int:
        """Stream the raw response of an endpoint into a file object without holding it in memory.

        The kinds and the endpoints they download are:

        - `yara_tlp`: all YARA rules of the TLP level `argument`, concatenated.
        - `yara_tlp_zip`: all YARA rules of the TLP level `argument` as a ZIP archive.
        - `yara_auto`: all rules generated by YARA-Signator, concatenated.
        - `yara_auto_zip`: all rules generated by YARA-Signator as a ZIP archive.
        - `yara_family_zip`: YARA rules of the family `argument` as a ZIP archive.
        - `bib`: BibTeX of all references.
        - `misp`: Malpedia as a MISP galaxy cluster.
        - `references`: all references with the families and actors they cover.
        - `apiscout_csv`: all non-zero ApiVector fingerprints as CSV. Requires login.

        Args:
            kind: One of the kinds above.
            destination: Binary file object that receives the body.
            argument: TLP level or family ID. Required for `yara_tlp`, `yara_tlp_zip` and
                `yara_family_zip`, and not allowed for the other kinds.
            progress: Function called after each chunk with the bytes written so far and the
                total size from the `Content-Length` header, or None if it is unknown.

        Returns:
            The number of bytes written to `destination`.

        Raises:
            InvalidArgumentError: If `kind` is unknown, or `argument` is missing or not allowed.
        """
        path = self._download_path(kind, argument)
        return self._stream(path, destination, progress)

    @staticmethod
    def _download_path(kind: str, argument: str | None) -> str:
        fixed = {
            "yara_auto": "get/yara/auto/raw",
            "yara_auto_zip": "get/yara/auto/zip",
            "bib": "get/bib",
            "misp": "get/misp",
            "references": "get/references",
            "apiscout_csv": "list/apiscout/csv",
        }
        if kind in fixed:
            if argument is not None:
                raise InvalidArgumentError(f"download kind {kind!r} takes no argument")
            return fixed[kind]
        if kind not in ("yara_tlp", "yara_tlp_zip", "yara_family_zip"):
            raise InvalidArgumentError(f"unknown download kind: {kind!r}")
        if argument is None:
            raise InvalidArgumentError(f"download kind {kind!r} requires an argument")
        if kind == "yara_tlp":
            return f"get/yara/{normalize_tlp(argument)}/raw"
        if kind == "yara_tlp_zip":
            return f"get/yara/{normalize_tlp(argument)}/zip"
        return f"get/yara/{_segment(argument)}/zip"

    def check_apikey(self) -> dict[str, Any]:
        """Check that the configured API token is valid."""
        return self._json("check/apikey")

    def get_version(self) -> Version:
        """Current version of the Malpedia dataset (commit number and date)."""
        return self._json("get/version")

    def list_families(self) -> list[str]:
        """IDs of all families."""
        return self._json("list/families")

    def get_families(self) -> dict[str, Family]:
        """Metadata of all families, keyed by family ID."""
        return self._json("get/families")

    def get_family(self, family_id: str) -> Family:
        """Metadata of one family.

        Args:
            family_id: Family ID, for example `win.emotet`.
        """
        return self._json(f"get/family/{_segment(family_id)}")

    def find_family(self, needle: str) -> list[FamilyMatch]:
        """Families whose name or synonyms contain `needle`.

        Args:
            needle: Text to search for.
        """
        return self._json(f"find/family/{_segment(needle)}")

    def list_actors(self) -> list[str]:
        """IDs of all actors."""
        return self._json("list/actors")

    def get_actors(self) -> dict[str, Actor]:
        """Metadata of all actors, keyed by actor name."""
        return self._json("get/actors")

    def get_actor(self, actor_id: str) -> Actor:
        """Metadata of one actor.

        Args:
            actor_id: Actor ID, for example `apt28`.
        """
        return self._json(f"get/actor/{_segment(actor_id)}")

    def find_actor(self, needle: str) -> list[ActorMatch]:
        """Actors whose name or synonyms contain `needle`.

        Args:
            needle: Text to search for.
        """
        return self._json(f"find/actor/{_segment(needle)}")

    def get_bib(self) -> str:
        """BibTeX of all references."""
        return self._text("get/bib")

    def get_bib_family(self, family_id: str) -> str:
        """BibTeX of the references of one family.

        Args:
            family_id: Family ID, for example `win.emotet`.
        """
        return self._text(f"get/bib/family/{_segment(family_id)}")

    def get_bib_actor(self, actor_id: str) -> str:
        """BibTeX of the references of one actor.

        Args:
            actor_id: Actor ID, for example `apt28`.
        """
        return self._text(f"get/bib/actor/{_segment(actor_id)}")

    def get_references(self) -> dict[str, Any]:
        """All references with the families and actors they cover."""
        return self._json("get/references")

    def get_misp(self) -> dict[str, Any]:
        """Malpedia as a MISP galaxy cluster."""
        return self._json("get/misp")

    def list_samples(self, family_id: str | None = None) -> list[Sample] | dict[str, list[Sample]]:
        """Samples of one family, or of all families. Requires login.

        Args:
            family_id: Family ID, or None for the samples of all families.

        Returns:
            A list of samples for one family, or a dict of such lists keyed by family ID.
        """
        if family_id is None:
            return self._json("list/samples")
        return self._json(f"list/samples/{_segment(family_id)}")

    def get_sample_info(self, sample_hash: str) -> SampleInfo:
        """Presence and status of a sample, without its content. Requires login.

        Args:
            sample_hash: MD5 or SHA256 of the sample.
        """
        return self._json(f"get/sample/{normalize_hash(sample_hash)}/info")

    def get_sample_raw(self, sample_hash: str) -> dict[str, bytes]:
        """The sample and its unpacked or dumped files. Requires login.

        Args:
            sample_hash: MD5 or SHA256 of the sample.

        Returns:
            File contents keyed by kind, such as `packed`, `unpacked` or `dump7_0x00390000`.
        """
        path = f"get/sample/{normalize_hash(sample_hash)}/raw"
        files = self._json(path)
        if not isinstance(files, dict):
            raise ResponseError(f"unexpected content from {self._http.base_url}{path}")
        return {name: self._decode(path, data) for name, data in files.items()}

    def get_sample_zip(self, sample_hash: str) -> bytes:
        """A ZIP archive of the sample and its unpacked or dumped files. Requires login.

        The archive is encrypted with the password `infected`.

        Args:
            sample_hash: MD5 or SHA256 of the sample.
        """
        path = f"get/sample/{normalize_hash(sample_hash)}/zip"
        return self._decode(path, self._json(path), "zipped")

    def list_yara(self) -> dict[str, list[YaraFile]]:
        """YARA rule files per family that the account may access."""
        return self._json("list/yara")

    def get_yara(self, family_id: str) -> YaraRules:
        """YARA rules of one family that the account may access.

        Args:
            family_id: Family ID, for example `win.emotet`.

        Returns:
            Rules as `{tlp: {filename: rule}}`.
        """
        return self._json(f"get/yara/{_segment(family_id)}")

    def get_yara_zip(self, family_id: str) -> bytes:
        """YARA rules of one family as a ZIP archive.

        Args:
            family_id: Family ID, for example `win.emotet`.
        """
        return self._bytes(f"get/yara/{_segment(family_id)}/zip")

    def get_yara_tlp(self, tlp: str) -> str:
        """All YARA rules of one TLP level, concatenated.

        Args:
            tlp: TLP level, for example `white` or `tlp_green`.
        """
        return self._text(f"get/yara/{normalize_tlp(tlp)}/raw")

    def get_yara_tlp_zip(self, tlp: str) -> bytes:
        """All YARA rules of one TLP level as a ZIP archive.

        Args:
            tlp: TLP level, for example `white` or `tlp_green`.
        """
        return self._bytes(f"get/yara/{normalize_tlp(tlp)}/zip")

    def get_yara_after(self, date: dt.date | str) -> YaraRules:
        """YARA rules changed after a date, for regular automated updates.

        Args:
            date: A date, or a string in the form YYYY-MM-DD.

        Returns:
            Rules as `{tlp: {filename: rule}}`.
        """
        return self._json(f"get/yara/after/{_date(date)}")

    def get_yara_auto(self) -> str:
        """All rules generated by YARA-Signator, concatenated."""
        return self._text("get/yara/auto/raw")

    def get_yara_auto_zip(self) -> bytes:
        """All rules generated by YARA-Signator as a ZIP archive."""
        return self._bytes("get/yara/auto/zip")

    def list_apiscout(self) -> dict[str, str]:
        """All non-zero ApiVector fingerprints, keyed by sample path. Requires login."""
        return self._json("list/apiscout")

    def list_apiscout_csv(self) -> str:
        """All non-zero ApiVector fingerprints as ApiScout-compatible CSV. Requires login."""
        return self._text("list/apiscout/csv")

    def scan_apiscout(self, apivector: str) -> Any:
        """Match a compressed ApiVector against Malpedia's fingerprints.

        Args:
            apivector: Compressed ApiVector as produced by ApiScout.
        """
        return self._json("scan/apiscout", content=apivector.encode())

    def scan_yara(self, family_id: str, rule: str | bytes) -> dict[str, Any]:
        """Scan all samples of one family with a YARA rule. Requires login.

        Args:
            family_id: Family ID whose samples are scanned.
            rule: YARA rule source.
        """
        content = rule.encode() if isinstance(rule, str) else rule
        return self._json(f"scan/yara/{_segment(family_id)}", content=content)
