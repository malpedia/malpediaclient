from __future__ import annotations

from collections.abc import Callable, Iterator

import httpx
import pytest

from malpedia import Client

Handler = Callable[[httpx.Request], httpx.Response]


class Recorder:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.response: httpx.Response | Handler = httpx.Response(200, json={})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if isinstance(self.response, httpx.Response):
            return self.response
        return self.response(request)

    @property
    def last(self) -> httpx.Request:
        return self.requests[-1]


@pytest.fixture
def recorder() -> Recorder:
    return Recorder()


@pytest.fixture
def client(recorder: Recorder) -> Iterator[Client]:
    with Client("secret", transport=httpx.MockTransport(recorder)) as c:
        yield c
