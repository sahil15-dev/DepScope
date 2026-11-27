import asyncio
import json
from collections import Counter
from collections.abc import AsyncIterator, Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import httpx
import pytest
from depscope import osv
from depscope.models import Assessment, Coordinate, Ecosystem, LookupStatus, Provenance
from depscope.osv import OSVClient, OSVConfig

from .helpers import ALPHA, BETA, MODIFIED, advisory

CONFIG = OSVConfig(request_interval=0, retry_base=0, max_retry_after=0)


def test_batch_correlation_per_query_pagination_and_shared_detail_cache() -> None:
    requests: list[httpx.Request] = []
    hit = {"id": "TEST-1", "modified": MODIFIED}

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.url.host == "api.osv.dev" and request.url.scheme == "https"
        if request.method == "GET":
            assert request.url.path == "/v1/vulns/TEST-1"
            return httpx.Response(200, json=advisory("TEST-1"))
        assert request.method == "POST" and request.url.path == "/v1/querybatch"
        query = json.loads(request.content)["queries"]
        alpha = {"package": {"ecosystem": "PyPI", "name": "alpha"}, "version": "1"}
        if len(requests) == 1:
            assert query == [
                alpha,
                {"package": {"ecosystem": "PyPI", "name": "beta"}, "version": "2"},
            ]
            return httpx.Response(
                200, json={"results": [{"vulns": [hit], "next_page_token": "n"}, {"vulns": [hit]}]}
            )
        assert query == [dict(alpha, page_token="n")]
        return httpx.Response(200, json={"results": [{"vulns": [hit]}]})

    async def run() -> None:
        async with OSVClient(config=CONFIG, transport=httpx.MockTransport(respond)) as client:
            first = await client.lookup([BETA, ALPHA, ALPHA])
            second = await client.lookup([ALPHA, BETA])
        assert first == second
        assert [item.coordinate for item in first] == [ALPHA, BETA]
        assert all(
            item.status is LookupStatus.COMPLETE and len(item.observations) == 1 for item in first
        )
        assert first[0].observations[0].advisory is first[1].observations[0].advisory

    asyncio.run(run())
    assert [item.method for item in requests] == ["POST", "POST", "GET"]


@pytest.mark.parametrize("version", ["*", ">=1", "https://invalid.invalid/x"])
def test_gateway_refuses_non_exact_coordinates(version: str) -> None:
    async def run() -> None:
        async with OSVClient() as client:
            with pytest.raises(ValueError, match="exact versions"):
                await client.lookup([Coordinate(Ecosystem.PYPI, "alpha", version)])

    asyncio.run(run())
    with pytest.raises(ValueError, match="explicit transport"):
        OSVClient(provenance=Provenance.OFFLINE_FIXTURE)


def test_retries_timeout_429_and_503_but_does_not_follow_redirect() -> None:
    calls = Counter[str]()

    def respond(request: httpx.Request) -> httpx.Response:
        calls[request.url.path] += 1
        if request.method == "GET":
            return httpx.Response(302, headers={"Location": "https://invalid.invalid/private"})
        if calls[request.url.path] == 1:
            raise httpx.ReadTimeout("simulated timeout", request=request)
        if calls[request.url.path] == 2:
            return httpx.Response(429, headers={"Retry-After": "0"})
        if calls[request.url.path] == 3:
            return httpx.Response(503, headers={"Retry-After": "invalid date"})
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "TEST-1"}]}]})

    (row,) = asyncio.run(_lookup(respond, config=replace(CONFIG, attempts=4)))
    assert calls == {"/v1/querybatch": 4, "/v1/vulns/TEST-1": 1}
    assert row.status is LookupStatus.PARTIAL
    assert row.observations[0].error == "unexpected_http_status"


@pytest.mark.parametrize("header", ["120", format_datetime(datetime.now(UTC) + timedelta(days=1))])
def test_rate_limit_does_not_retry_before_long_retry_after(header: str) -> None:
    calls = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429, headers={"Retry-After": header})

    (row,) = asyncio.run(_lookup(respond))
    assert calls == 1
    assert row.status is LookupStatus.FAILED
    assert row.diagnostics == ("rate_limited",)


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (httpx.ConnectError, "request_failed"),
        (httpx.ConnectTimeout, "request_timeout"),
    ],
)
def test_retry_attempt_limit(error: type[httpx.RequestError], code: str) -> None:
    calls = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise error("simulated failure", request=request)

    (row,) = asyncio.run(_lookup(respond))
    assert calls == CONFIG.attempts
    assert row.diagnostics == (code,)


def test_partial_batch_failure_never_becomes_a_successful_empty_assessment() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": [{}, {"vulns": "invalid"}]})

    first, second = asyncio.run(_lookup(respond, keys=[ALPHA, BETA]))
    assert (first.status, first.observations) == (LookupStatus.COMPLETE, ())
    assert (second.status, second.diagnostics) == (LookupStatus.FAILED, ("malformed_query_result",))


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (b"<html>", "malformed_response"),
        (b'{"results": []}', "uncorrelated_batch_response"),
        (b"[]", "expected_object"),
        (b'{"results":[{"next_page_token":null}]}', "malformed_query_result"),
        (b'{"results":[{"vulns":[{"id":"../invalid"}]}]}', "malformed_query_result"),
        (b'{"results":[{"unexpected":true}]}', "malformed_query_result"),
    ],
)
def test_osv_malformed_response_cannot_report_no_findings(body: bytes, code: str) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body)

    (row,) = asyncio.run(_lookup(respond))
    assert row.status is LookupStatus.FAILED
    assert row.diagnostics == (code,)


@pytest.mark.parametrize(
    ("config", "code"),
    [
        (replace(CONFIG, max_pages=1), "pagination_limit"),
        (CONFIG, "repeated_page_token"),
        (replace(CONFIG, max_ids_per_coordinate=1), "advisory_id_limit"),
        (replace(CONFIG, max_pages=1, max_details=1), "detail_budget_exhausted"),
    ],
)
def test_budget_diagnostics_preserve_already_discovered_ids(config: OSVConfig, code: str) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=advisory(request.url.path.rsplit("/", 1)[-1]))
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [{"id": "TEST-A"}, {"id": "TEST-B"}],
                        "next_page_token": "repeat",
                    }
                ]
            },
        )

    (row,) = asyncio.run(_lookup(respond, config=config))
    assert row.status is LookupStatus.PARTIAL
    assert code in row.diagnostics
    assert row.observations[0].discovery.id == "TEST-A"


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (advisory("OTHER"), "malformed_advisory"),
        (advisory("TEST-A", modified="2024-01-01T00:00:00Z"), "stale_advisory"),
        (advisory("TEST-A", withdrawn="not a date"), "malformed_advisory"),
    ],
)
def test_bad_or_outdated_detail_preserves_discovery(body: object, code: str) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=body)
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [{"id": "TEST-A", "modified": MODIFIED}],
                    }
                ]
            },
        )

    (row,) = asyncio.run(_lookup(respond))
    (match,) = row.observations
    assert (row.status, match.discovery.id, match.advisory, match.error) == (
        LookupStatus.PARTIAL,
        "TEST-A",
        None,
        code,
    )


def test_cache_eviction_expiration_and_advisory_update(monkeypatch: pytest.MonkeyPatch) -> None:
    tick = 0.0
    query_count = 0
    detail_count = 0
    latest = MODIFIED
    config = replace(CONFIG, cache_entries=1, query_ttl=2, detail_ttl=10, batch_size=1)
    monkeypatch.setattr(osv, "monotonic", lambda: tick)

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal query_count, detail_count
        if request.method == "GET":
            detail_count += 1
            return httpx.Response(200, json=advisory("TEST-1", modified=latest))
        query_count += 1
        return httpx.Response(
            200, json={"results": [{"vulns": [{"id": "TEST-1", "modified": latest}]}]}
        )

    async def run() -> None:
        nonlocal tick, latest
        async with OSVClient(config=config, transport=httpx.MockTransport(respond)) as client:
            await client.lookup([ALPHA, BETA])
            await client.lookup([ALPHA])  # Evicted by beta.
            await client.lookup([ALPHA])
            assert (query_count, detail_count) == (3, 1)
            tick = 3
            latest = "2025-01-03T00:00:00Z"
            await client.lookup([ALPHA])
            assert (query_count, detail_count) == (4, 2)
            tick = 20
            await client.lookup([ALPHA])
            assert (query_count, detail_count) == (5, 3)

    asyncio.run(run())


class _Chunks(httpx.AsyncByteStream):
    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield b"a" * 15
        yield b"b" * 15


@pytest.mark.parametrize(
    ("response", "code"),
    [
        (httpx.Response(200, content=b"x" * 30), "response_too_large"),
        (httpx.Response(200, stream=_Chunks()), "response_too_large"),
        (
            httpx.Response(200, stream=_Chunks(), headers={"Content-Encoding": "gzip"}),
            "unsupported_response_encoding",
        ),
    ],
)
def test_bounded_response_reads(response: httpx.Response, code: str) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        return response

    (row,) = asyncio.run(_lookup(respond, config=replace(CONFIG, max_response_bytes=20)))
    assert row.diagnostics == (code,)


def test_concurrency_and_scan_deadline() -> None:
    active = 0
    peak = 0

    async def respond(request: httpx.Request) -> httpx.Response:
        nonlocal active, peak
        if request.method == "POST":
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "vulns": [
                                {"id": identifier} for identifier in ("TEST-A", "TEST-B", "TEST-C")
                            ],
                        }
                    ]
                },
            )
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.sleep(0.001 if request.url.path.endswith("TEST-A") else 2)
            return httpx.Response(200, json=advisory("TEST-A"))
        finally:
            active -= 1

    async def run() -> Assessment:
        config = replace(CONFIG, concurrency=2, scan_timeout=0.18)
        async with OSVClient(config=config, transport=httpx.MockTransport(respond)) as client:
            (row,) = await client.lookup([ALPHA])
        return row

    row = asyncio.run(run())
    assert peak == 2
    assert row.status is LookupStatus.PARTIAL
    assert row.observations[0].advisory is not None
    assert row.diagnostics == ("scan_deadline_exceeded",)


async def _lookup(
    respond: Callable[[httpx.Request], httpx.Response],
    *,
    keys: list[Coordinate] | None = None,
    config: OSVConfig = CONFIG,
) -> tuple[Assessment, ...]:
    async with OSVClient(config=config, transport=httpx.MockTransport(respond)) as client:
        return await client.lookup(keys or [ALPHA])
