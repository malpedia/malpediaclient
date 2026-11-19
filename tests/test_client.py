from __future__ import annotations

import base64
import datetime as dt
import gzip
import io
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from malpedia import (
    APIError,
    AuthenticationError,
    Client,
    InvalidArgumentError,
    NotFoundError,
    ResponseError,
    TransportError,
)
from tests.conftest import Recorder

MD5 = "8da534e1710b9d23778f55eb5c39e0db"
SHA256 = "6ada5c313fa15bd4aa8e43638ded5faacc1737064e66b40ff64a329c12f7a5ef"

ENDPOINTS: list[tuple[Callable[[Client], Any], str]] = [
    (lambda c: c.check_apikey(), "check/apikey"),
    (lambda c: c.find_actor("fancy bear"), "find/actor/fancy%20bear"),
    (lambda c: c.find_family("emo/tet"), "find/family/emo%2Ftet"),
    (lambda c: c.get_actor("apt28"), "get/actor/apt28"),
    (lambda c: c.get_actors(), "get/actors"),
    (lambda c: c.get_bib(), "get/bib"),
    (lambda c: c.get_bib_actor("apt28"), "get/bib/actor/apt28"),
    (lambda c: c.get_bib_family("win.emotet"), "get/bib/family/win.emotet"),
    (lambda c: c.get_families(), "get/families"),
    (lambda c: c.get_family("win.emotet"), "get/family/win.emotet"),
    (lambda c: c.get_misp(), "get/misp"),
    (lambda c: c.get_references(), "get/references"),
    (lambda c: c.get_sample_info(MD5), f"get/sample/{MD5}/info"),
    (lambda c: c.get_sample_info(SHA256.upper()), f"get/sample/{SHA256}/info"),
    (lambda c: c.get_version(), "get/version"),
    (lambda c: c.get_yara("win.emotet"), "get/yara/win.emotet"),
    (lambda c: c.get_yara_zip("win.emotet"), "get/yara/win.emotet/zip"),
    (lambda c: c.get_yara_tlp("white"), "get/yara/tlp_white/raw"),
    (lambda c: c.get_yara_tlp_zip("TLP:AMBER"), "get/yara/tlp_amber/zip"),
    (lambda c: c.get_yara_after("2024-01-31"), "get/yara/after/2024-01-31"),
    (lambda c: c.get_yara_after(dt.date(2024, 2, 1)), "get/yara/after/2024-02-01"),
    (lambda c: c.get_yara_auto(), "get/yara/auto/raw"),
    (lambda c: c.get_yara_auto_zip(), "get/yara/auto/zip"),
    (lambda c: c.list_actors(), "list/actors"),
    (lambda c: c.list_apiscout(), "list/apiscout"),
    (lambda c: c.list_apiscout_csv(), "list/apiscout/csv"),
    (lambda c: c.list_families(), "list/families"),
    (lambda c: c.list_samples(), "list/samples"),
    (lambda c: c.list_samples("win.emotet"), "list/samples/win.emotet"),
    (lambda c: c.list_yara(), "list/yara"),
]


@pytest.mark.parametrize(("call", "path"), ENDPOINTS, ids=[path for _, path in ENDPOINTS])
def test_get_endpoints(client: Client, recorder: Recorder, call: Callable[[Client], Any], path: str) -> None:
    call(client)
    assert recorder.last.method == "GET"
    assert recorder.last.url.raw_path.decode() == f"/api/{path}"
    assert recorder.last.headers["Authorization"] == "apitoken secret"


def test_sample_raw_and_zip_are_decoded(client: Client, recorder: Recorder) -> None:
    recorder.response = httpx.Response(200, json={"packed": base64.b64encode(b"MZ").decode()})
    assert client.get_sample_raw(SHA256) == {"packed": b"MZ"}
    assert recorder.last.url.path == f"/api/get/sample/{SHA256}/raw"

    recorder.response = httpx.Response(200, json={"zipped": base64.b64encode(b"PK").decode()})
    assert client.get_sample_zip(MD5) == b"PK"
    assert recorder.last.url.path == f"/api/get/sample/{MD5}/zip"


def test_text_and_binary_responses(client: Client, recorder: Recorder) -> None:
    recorder.response = httpx.Response(200, text="@online{x}")
    assert client.get_bib() == "@online{x}"
    recorder.response = httpx.Response(200, content=b"PK\x03\x04")
    assert client.get_yara_auto_zip() == b"PK\x03\x04"


def test_scan_endpoints_post_raw_body(client: Client, recorder: Recorder) -> None:
    recorder.response = httpx.Response(200, json={"detail": "Scan complete."})
    assert client.scan_yara("win.emotet", "rule a { condition: true }") == {"detail": "Scan complete."}
    assert recorder.last.method == "POST"
    assert recorder.last.url.path == "/api/scan/yara/win.emotet"
    assert recorder.last.content == b"rule a { condition: true }"

    client.scan_apiscout("A132QA")
    assert recorder.last.method == "POST"
    assert recorder.last.url.path == "/api/scan/apiscout"
    assert recorder.last.content == b"A132QA"


@pytest.mark.parametrize(
    ("status", "body", "error", "detail"),
    [
        (401, {"detail": "Invalid token."}, AuthenticationError, "Invalid token."),
        (403, {"detail": "Authentication credentials were not provided."}, AuthenticationError, None),
        (404, {"detail": "No Family matches the given query."}, NotFoundError, None),
        (500, None, APIError, "Internal Server Error"),
    ],
)
def test_error_mapping(
    client: Client, recorder: Recorder, status: int, body: Any, error: type[APIError], detail: str | None
) -> None:
    recorder.response = (
        httpx.Response(status, json=body)
        if body is not None
        else httpx.Response(status, text="<html>", headers={"content-type": "text/html"})
    )
    with pytest.raises(error) as excinfo:
        client.get_family("x")
    assert type(excinfo.value) is error
    assert excinfo.value.status_code == status
    assert excinfo.value.detail == (detail or body["detail"])


def test_transport_errors_are_wrapped(recorder: Recorder) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    recorder.response = boom
    with Client(transport=httpx.MockTransport(recorder)) as c, pytest.raises(TransportError, match="refused"):
        c.get_version()


@pytest.mark.parametrize(
    ("call", "match"),
    [
        pytest.param(lambda c: c.get_sample_info("not-a-hash"), "MD5 or SHA256", id="bad-hash"),
        pytest.param(lambda c: c.get_sample_raw("a" * 40), "MD5 or SHA256", id="sha1"),
        pytest.param(lambda c: c.get_yara_tlp("red"), "TLP must be", id="bad-tlp"),
        pytest.param(lambda c: c.get_yara_after("31.01.2024"), "YYYY-MM-DD", id="bad-date"),
        pytest.param(lambda c: c.get_family(""), "invalid path parameter", id="empty-id"),
    ],
)
def test_invalid_arguments_fail_before_any_request(
    client: Client, recorder: Recorder, call: Callable[[Client], Any], match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        call(client)
    assert recorder.requests == []


def test_anonymous_and_basic_auth(recorder: Recorder) -> None:
    with Client(transport=httpx.MockTransport(recorder)) as c:
        c.get_version()
    assert "Authorization" not in recorder.last.headers

    with Client(username="rony", password="pw", transport=httpx.MockTransport(recorder)) as c:
        c.get_version()
    assert recorder.last.headers["Authorization"] == "Basic " + base64.b64encode(b"rony:pw").decode()


@pytest.mark.parametrize(
    "kwargs",
    [{"apitoken": "t", "username": "u", "password": "p"}, {"username": "u"}, {"password": "p"}],
)
def test_conflicting_credentials(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=r"API token or a username|given together"):
        Client(**kwargs)


def test_custom_base_url(recorder: Recorder) -> None:
    with Client(base_url="https://example.test/api", transport=httpx.MockTransport(recorder)) as c:
        c.list_families()
    assert str(recorder.last.url) == "https://example.test/api/list/families"


@pytest.mark.parametrize(
    ("call", "response"),
    [
        pytest.param(lambda c: c.get_family("x"), httpx.Response(200, text="<html>"), id="html-instead-of-json"),
        pytest.param(lambda c: c.get_sample_zip(MD5), httpx.Response(200, json={}), id="zip-missing-key"),
        pytest.param(lambda c: c.get_sample_raw(MD5), httpx.Response(200, json={"packed": "%%"}), id="bad-base64"),
        pytest.param(lambda c: c.get_sample_raw(MD5), httpx.Response(200, json=["x"]), id="raw-not-a-dict"),
    ],
)
def test_malformed_responses_raise_response_error(
    client: Client, recorder: Recorder, call: Callable[[Client], Any], response: httpx.Response
) -> None:
    recorder.response = response
    with pytest.raises(ResponseError):
        call(client)


@pytest.mark.parametrize("segment", [".", ".."])
def test_dot_segments_are_rejected(client: Client, recorder: Recorder, segment: str) -> None:
    with pytest.raises(InvalidArgumentError):
        client.find_family(segment)
    assert recorder.requests == []


def retrying_client(recorder: Recorder, sleeps: list[float], **kwargs: Any) -> Client:
    return Client(transport=httpx.MockTransport(recorder), sleep=sleeps.append, **kwargs)


def test_retry_on_503_then_success(recorder: Recorder) -> None:
    responses = iter([httpx.Response(503), httpx.Response(200, json={"version": 1})])
    recorder.response = lambda request: next(responses)
    sleeps: list[float] = []
    with retrying_client(recorder, sleeps) as c:
        assert c.get_version() == {"version": 1}
    assert len(recorder.requests) == 2
    assert sleeps == [1]


def test_retry_after_is_honored(recorder: Recorder) -> None:
    responses = iter(
        [
            httpx.Response(429, headers={"Retry-After": "7"}),
            httpx.Response(502, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}),
            httpx.Response(200, json={}),
        ]
    )
    recorder.response = lambda request: next(responses)
    sleeps: list[float] = []
    with retrying_client(recorder, sleeps) as c:
        c.get_version()
    assert sleeps == [7, 2]


def test_long_retry_after_gives_up(recorder: Recorder) -> None:
    recorder.response = httpx.Response(429, headers={"Retry-After": "3600"})
    sleeps: list[float] = []
    with retrying_client(recorder, sleeps) as c, pytest.raises(APIError) as excinfo:
        c.get_version()
    assert excinfo.value.status_code == 429
    assert sleeps == []


def test_retry_gives_up_after_status_retries(recorder: Recorder) -> None:
    recorder.response = httpx.Response(503, json={"detail": "Unavailable."})
    sleeps: list[float] = []
    with retrying_client(recorder, sleeps, status_retries=3) as c, pytest.raises(APIError) as excinfo:
        c.get_version()
    assert excinfo.value.status_code == 503
    assert len(recorder.requests) == 4
    assert sleeps == [1, 2, 4]


def test_post_is_never_retried(recorder: Recorder) -> None:
    recorder.response = httpx.Response(503)
    sleeps: list[float] = []
    with retrying_client(recorder, sleeps) as c, pytest.raises(APIError):
        c.scan_apiscout("A132QA")
    assert len(recorder.requests) == 1
    assert sleeps == []


def test_other_statuses_are_not_retried(recorder: Recorder) -> None:
    recorder.response = httpx.Response(500)
    sleeps: list[float] = []
    with retrying_client(recorder, sleeps) as c, pytest.raises(APIError):
        c.get_version()
    assert len(recorder.requests) == 1
    assert sleeps == []


def test_download_writes_bytes_and_reports_progress(recorder: Recorder) -> None:
    recorder.response = httpx.Response(200, content=b"PK\x03\x04" * 4)
    calls: list[tuple[int, int | None]] = []
    destination = io.BytesIO()
    with retrying_client(recorder, []) as c:
        size = c.download("yara_tlp_zip", destination, argument="TLP:GREEN", progress=lambda n, t: calls.append((n, t)))
    assert size == 16
    assert destination.getvalue() == b"PK\x03\x04" * 4
    assert calls
    assert calls[-1] == (16, 16)
    assert recorder.last.method == "GET"
    assert recorder.last.url.path == "/api/get/yara/tlp_green/zip"


@pytest.mark.parametrize(
    ("kind", "argument", "path"),
    [
        ("yara_tlp", "white", "get/yara/tlp_white/raw"),
        ("yara_auto", None, "get/yara/auto/raw"),
        ("yara_auto_zip", None, "get/yara/auto/zip"),
        ("yara_family_zip", "win.emotet", "get/yara/win.emotet/zip"),
        ("bib", None, "get/bib"),
        ("misp", None, "get/misp"),
        ("references", None, "get/references"),
        ("apiscout_csv", None, "list/apiscout/csv"),
    ],
)
def test_download_endpoints(client: Client, recorder: Recorder, kind: str, argument: str | None, path: str) -> None:
    client.download(kind, io.BytesIO(), argument=argument)
    assert recorder.last.url.raw_path.decode() == f"/api/{path}"


def test_download_without_content_length_reports_unknown_total(recorder: Recorder) -> None:
    recorder.response = httpx.Response(200, content=iter([b"ab", b"cde"]))
    calls: list[tuple[int, int | None]] = []
    with retrying_client(recorder, []) as c:
        assert c.download("bib", io.BytesIO(), progress=lambda n, t: calls.append((n, t))) == 5
    assert calls == [(5, None)]


def test_download_maps_not_found(client: Client, recorder: Recorder) -> None:
    recorder.response = httpx.Response(404, json={"detail": "Not found."})
    with pytest.raises(NotFoundError) as excinfo:
        client.download("yara_family_zip", io.BytesIO(), argument="nope")
    assert excinfo.value.detail == "Not found."


def test_download_retries_on_503(recorder: Recorder) -> None:
    responses = iter([httpx.Response(503), httpx.Response(200, content=b"ok")])
    recorder.response = lambda request: next(responses)
    sleeps: list[float] = []
    destination = io.BytesIO()
    with retrying_client(recorder, sleeps) as c:
        assert c.download("misp", destination) == 2
    assert destination.getvalue() == b"ok"
    assert sleeps == [1]


@pytest.mark.parametrize(
    ("kind", "argument"),
    [
        pytest.param("nope", None, id="unknown-kind"),
        pytest.param("yara_tlp", None, id="missing-argument"),
        pytest.param("yara_family_zip", None, id="missing-family"),
        pytest.param("bib", "x", id="extra-argument"),
        pytest.param("yara_tlp", "red", id="bad-tlp"),
        pytest.param("yara_family_zip", "..", id="bad-family"),
    ],
)
def test_download_invalid_arguments_fail_before_any_request(
    client: Client, recorder: Recorder, kind: str, argument: str | None
) -> None:
    with pytest.raises(InvalidArgumentError):
        client.download(kind, io.BytesIO(), argument=argument)
    assert recorder.requests == []


def test_download_progress_has_no_total_for_compressed_bodies(recorder: Recorder) -> None:
    body = gzip.compress(b"x" * 1000)
    recorder.response = httpx.Response(
        200, content=body, headers={"Content-Encoding": "gzip", "Content-Length": str(len(body))}
    )
    calls: list[tuple[int, int | None]] = []
    destination = io.BytesIO()
    with retrying_client(recorder, []) as c:
        assert c.download("bib", destination, progress=lambda n, t: calls.append((n, t))) == 1000
    assert destination.getvalue() == b"x" * 1000
    assert calls[-1] == (1000, None)
