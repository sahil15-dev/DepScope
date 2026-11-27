from uuid import uuid4

import httpx
import pytest


def pytest_configure(config: pytest.Config) -> None:
    if config.getoption("basetemp") is None:
        artifacts = config.rootpath / "artifacts"
        artifacts.mkdir(exist_ok=True)
        config.option.basetemp = str(artifacts / f"pytest-{uuid4().hex}")


@pytest.fixture(autouse=True)
def forbid_live_http(monkeypatch: pytest.MonkeyPatch) -> None:
    async def reject(self: httpx.AsyncHTTPTransport, request: httpx.Request) -> httpx.Response:
        pytest.fail(f"Unexpected live HTTP request to {request.url.host}")

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", reject)
