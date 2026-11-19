from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from malpedia import Client, NotFoundError

pytestmark = pytest.mark.live

TOKEN = os.environ.get("MALPEDIA_API_TOKEN")
needs_token = pytest.mark.skipif(not TOKEN, reason="MALPEDIA_API_TOKEN is not set")


@pytest.fixture(scope="module")
def api() -> Iterator[Client]:
    with Client(TOKEN) as c:
        yield c


def test_public_endpoints(api: Client) -> None:
    assert isinstance(api.get_version()["version"], int)
    assert "win.emotet" in api.list_families()
    assert "apt28" in api.list_actors()
    assert any(f["name"] == "win.emotet" for f in api.find_family("emotet"))
    assert api.get_family("win.emotet")["common_name"] == "Emotet"
    assert api.get_bib_family("win.emotet").startswith("@")
    with pytest.raises(NotFoundError):
        api.get_family("win.does_not_exist")


@needs_token
def test_registered_endpoints(api: Client) -> None:
    assert api.check_apikey() == {"detail": "Valid token."}
    samples = api.list_samples("win.emotet")
    assert isinstance(samples, list)
    info = api.get_sample_info(samples[0]["sha256"])
    assert info["family"] == "win.emotet"
    assert api.get_sample_info(info["md5"])["sha256"] == info["sha256"]
    assert api.get_yara_zip("win.emotet").startswith(b"PK")
