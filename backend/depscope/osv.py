import asyncio
import math
import random
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from time import monotonic
from types import TracebackType
from typing import Self

import httpx

from ._json import InvalidPayload, array_value, decode_json, object_value
from .advisories import advisory_id, parse_advisory, timestamp
from .identity import exact_version, package_name
from .models import (
    Advisory,
    Assessment,
    Coordinate,
    Discovery,
    LookupStatus,
    Observation,
    Provenance,
)

_API = "https://api.osv.dev"


@dataclass(frozen=True, slots=True)
class OSVConfig:
    batch_size: int = 100
    concurrency: int = 6
    attempts: int = 3
    request_timeout: float = 8
    scan_timeout: float = 45
    retry_base: float = 0.25
    max_retry_after: float = 5
    request_interval: float = 0.05
    max_pages: int = 8
    max_ids_per_coordinate: int = 100
    max_details: int = 256
    max_response_bytes: int = 1_000_000
    cache_entries: int = 256
    query_ttl: float = 300
    detail_ttl: float = 900

    def __post_init__(self) -> None:
        if (
            min(
                self.batch_size,
                self.concurrency,
                self.attempts,
                self.max_pages,
                self.max_ids_per_coordinate,
                self.max_details,
                self.max_response_bytes,
                self.cache_entries,
            )
            < 1
        ):
            raise ValueError("OSV request and cache limits must be positive")
        delays = (
            self.request_timeout,
            self.scan_timeout,
            self.retry_base,
            self.max_retry_after,
            self.request_interval,
            self.query_ttl,
            self.detail_ttl,
        )
        if any(not math.isfinite(delay) or delay < 0 for delay in delays) or not min(delays[:2]):
            raise ValueError("OSV durations must be finite and timeouts positive")


class _Cache[K, V]:
    def __init__(self, limit: int, ttl: float) -> None:
        self._entries: OrderedDict[K, tuple[float, V]] = OrderedDict()
        self._limit = limit
        self._ttl = ttl

    def get(self, key: K) -> V | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        expires, value = entry
        if expires <= monotonic():
            del self._entries[key]
            return None
        self._entries.move_to_end(key)
        return value

    def put(self, key: K, value: V) -> None:
        self._entries[key] = (monotonic() + self._ttl, value)
        self._entries.move_to_end(key)
        if len(self._entries) > self._limit:
            self._entries.popitem(last=False)


class _RequestError(Exception):
    def __init__(
        self, code: str, *, retryable: bool = False, retry_after: float | None = None
    ) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable
        self.retry_after = retry_after


def _retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        if value.isascii() and value.isdecimal():
            return float(value)
        date = parsedate_to_datetime(value)
        if date.tzinfo is None:
            date = date.replace(tzinfo=UTC)
        return max(0.0, (date - datetime.now(UTC)).total_seconds())
    except (ValueError, TypeError, OverflowError):
        return None


def _query(coordinate: Coordinate, token: str | None) -> dict[str, object]:
    result: dict[str, object] = {
        "package": {"name": coordinate.name, "ecosystem": coordinate.ecosystem.value},
        "version": coordinate.version,
    }
    if token is not None:
        result["page_token"] = token
    return result


def _page(value: object) -> tuple[list[Discovery], str | None]:
    result = object_value(value)
    if result and "vulns" not in result and "next_page_token" not in result:
        raise InvalidPayload("unrecognized_query_result")
    token = result.get("next_page_token", "")
    if not isinstance(token, str) or len(token) > 2048:
        raise InvalidPayload("invalid_page_token")
    discoveries: list[Discovery] = []
    for item in array_value(result.get("vulns", [])):
        hit = object_value(item)
        modified = timestamp(hit["modified"]) if "modified" in hit else None
        discoveries.append(Discovery(advisory_id(hit.get("id")), modified))
    return discoveries, token or None


def _remember(discoveries: dict[str, Discovery], item: Discovery) -> None:
    previous = discoveries.get(item.id)
    if previous is None or (
        item.modified and (not previous.modified or item.modified > previous.modified)
    ):
        discoveries[item.id] = item


@dataclass(slots=True)
class _DiscoveryState:
    hits: dict[str, Discovery] = field(default_factory=dict)
    tokens: set[str] = field(default_factory=set)
    error: str | None = None


class OSVClient:
    """Bounded OSV gateway. Inject an HTTPX transport for offline tests and fixtures."""

    def __init__(
        self,
        *,
        config: OSVConfig = OSVConfig(),
        transport: httpx.AsyncBaseTransport | None = None,
        provenance: Provenance = Provenance.LIVE_OSV,
    ) -> None:
        if provenance is Provenance.OFFLINE_FIXTURE and transport is None:
            raise ValueError("Offline fixture mode requires an explicit transport")
        self.provenance = provenance
        self._config = config
        self._http = httpx.AsyncClient(
            base_url=_API,
            transport=transport,
            timeout=config.request_timeout,
            limits=httpx.Limits(max_connections=config.concurrency),
            trust_env=False,
            follow_redirects=False,
            headers={"Accept-Encoding": "identity"},
        )
        self._connections = asyncio.Semaphore(config.concurrency)
        self._pace = asyncio.Lock()
        self._next_request = 0.0
        self._query_cache: _Cache[Coordinate, tuple[Discovery, ...]] = _Cache(
            config.cache_entries, config.query_ttl
        )
        self._detail_cache: _Cache[str, Advisory] = _Cache(config.cache_entries, config.detail_ttl)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self._http.aclose()

    async def _read(self, response: httpx.Response) -> bytes:
        if response.headers.get("Content-Encoding", "identity").lower() != "identity":
            raise _RequestError("unsupported_response_encoding")
        limit = self._config.max_response_bytes
        length = response.headers.get("Content-Length", "")
        if length.isascii() and length.isdecimal() and (len(length) > 16 or int(length) > limit):
            raise _RequestError("response_too_large")
        if response.is_stream_consumed:
            if len(response.content) > limit:
                raise _RequestError("response_too_large")
            return response.content
        content = bytearray()
        async for chunk in response.aiter_raw():
            if len(content) + len(chunk) > limit:
                raise _RequestError("response_too_large")
            content.extend(chunk)
        return bytes(content)

    async def _once(self, method: str, path: str, payload: dict[str, object] | None) -> object:
        async with self._connections:
            async with self._pace:
                await asyncio.sleep(max(0, self._next_request - monotonic()))
                self._next_request = monotonic() + self._config.request_interval
            async with self._http.stream(method, path, json=payload) as response:
                status = response.status_code
                if status == 200:
                    return decode_json(await self._read(response))
                if status == 429:
                    raise _RequestError(
                        "rate_limited",
                        retryable=True,
                        retry_after=_retry_after(response.headers.get("Retry-After")),
                    )
                if status in (408, 500, 502, 503, 504):
                    raise _RequestError(
                        "upstream_unavailable",
                        retryable=True,
                        retry_after=_retry_after(response.headers.get("Retry-After")),
                    )
                raise _RequestError(
                    "advisory_not_found" if status == 404 else "unexpected_http_status"
                )

    async def _request(
        self,
        method: str,
        path: str,
        deadline: float,
        payload: dict[str, object] | None = None,
    ) -> object:
        config = self._config
        try:
            async with asyncio.timeout_at(deadline):
                for attempt in range(config.attempts):
                    if asyncio.get_running_loop().time() >= deadline:
                        raise _RequestError("scan_deadline_exceeded")
                    try:
                        return await self._once(method, path, payload)
                    except InvalidPayload as exc:
                        raise _RequestError("malformed_response") from exc
                    except httpx.TimeoutException:
                        error = _RequestError("request_timeout", retryable=True)
                    except httpx.RequestError:
                        error = _RequestError("request_failed", retryable=True)
                    except _RequestError as exc:
                        error = exc
                    if not error.retryable or attempt + 1 >= config.attempts:
                        raise error
                    if error.retry_after is not None and error.retry_after > config.max_retry_after:
                        raise error
                    delay = min(config.max_retry_after, config.retry_base * 2 ** min(attempt, 10))
                    jittered = min(config.max_retry_after, delay + random.uniform(0, delay / 2))
                    await asyncio.sleep(max(error.retry_after or 0, jittered))
        except TimeoutError as exc:
            raise _RequestError("scan_deadline_exceeded") from exc
        raise AssertionError("OSV attempts must be positive")

    async def _discover_batch(
        self,
        coordinates: list[Coordinate],
        deadline: float,
    ) -> dict[Coordinate, _DiscoveryState]:
        states = {coordinate: _DiscoveryState() for coordinate in coordinates}
        active: dict[Coordinate, str | None] = dict.fromkeys(coordinates)
        for _ in range(self._config.max_pages):
            if not active:
                break
            try:
                payload: dict[str, object] = {
                    "queries": [_query(key, token) for key, token in active.items()]
                }
                body = object_value(
                    await self._request("POST", "/v1/querybatch", deadline, payload)
                )
                rows = array_value(body.get("results"))
                if len(rows) != len(active):
                    raise InvalidPayload("uncorrelated_batch_response")
            except (_RequestError, InvalidPayload) as exc:
                for coordinate in active:
                    states[coordinate].error = (
                        exc.code if isinstance(exc, _RequestError) else str(exc)
                    )
                return states

            next_page: dict[Coordinate, str | None] = {}
            for coordinate, row in zip(active, rows, strict=True):
                state = states[coordinate]
                try:
                    discoveries, token = _page(row)
                except InvalidPayload:
                    state.error = "malformed_query_result"
                    continue
                for discovery in discoveries:
                    if (
                        discovery.id not in state.hits
                        and len(state.hits) >= self._config.max_ids_per_coordinate
                    ):
                        state.error = "advisory_id_limit"
                        break
                    _remember(state.hits, discovery)
                if state.error:
                    continue
                if token is None:
                    self._query_cache.put(coordinate, tuple(state.hits.values()))
                elif token in state.tokens:
                    state.error = "repeated_page_token"
                else:
                    state.tokens.add(token)
                    next_page[coordinate] = token
            active = next_page
        for coordinate in active:
            states[coordinate].error = "pagination_limit"
        return states

    async def _detail(self, hit: Discovery, deadline: float) -> tuple[Advisory | None, str | None]:
        cached = self._detail_cache.get(hit.id)
        if cached is not None and (hit.modified is None or cached.modified >= hit.modified):
            return cached, None
        try:
            advisory = parse_advisory(
                await self._request("GET", f"/v1/vulns/{hit.id}", deadline),
                hit.id,
            )
        except _RequestError as exc:
            return None, exc.code
        except InvalidPayload:
            return None, "malformed_advisory"
        if hit.modified is not None and advisory.modified < hit.modified:
            return None, "stale_advisory"
        self._detail_cache.put(hit.id, advisory)
        return advisory, None

    async def lookup(self, coordinates: Iterable[Coordinate]) -> tuple[Assessment, ...]:
        keys = sorted(set(coordinates))
        for key in keys:
            if (
                package_name(key.ecosystem, key.name) != key.name
                or exact_version(key.ecosystem, key.version) is None
            ):
                raise ValueError("OSV queries require normalized names and exact versions")
        deadline = asyncio.get_running_loop().time() + self._config.scan_timeout
        states: dict[Coordinate, _DiscoveryState] = {}
        pending: list[Coordinate] = []
        for key in keys:
            cached = self._query_cache.get(key)
            if cached is None:
                pending.append(key)
            else:
                states[key] = _DiscoveryState({hit.id: hit for hit in cached})
        for offset in range(0, len(pending), self._config.batch_size):
            states.update(
                await self._discover_batch(
                    pending[offset : offset + self._config.batch_size], deadline
                )
            )

        hits: dict[str, Discovery] = {}
        for key in keys:
            for hit in states[key].hits.values():
                _remember(hits, hit)
        selected = sorted(hits.values(), key=lambda item: item.id)[: self._config.max_details]
        details: dict[str, tuple[Advisory | None, str | None]] = {}
        for offset in range(0, len(selected), self._config.concurrency):
            chunk = selected[offset : offset + self._config.concurrency]
            responses = await asyncio.gather(*(self._detail(hit, deadline) for hit in chunk))
            details.update((hit.id, result) for hit, result in zip(chunk, responses, strict=True))

        return tuple(self._assess(key, states[key], details) for key in keys)

    @staticmethod
    def _assess(
        coordinate: Coordinate,
        state: _DiscoveryState,
        details: dict[str, tuple[Advisory | None, str | None]],
    ) -> Assessment:
        observations = tuple(
            Observation(
                state.hits[identifier], *details.get(identifier, (None, "detail_budget_exhausted"))
            )
            for identifier in sorted(state.hits)
        )
        diagnostics = {item.error for item in observations if item.error}
        if state.error:
            diagnostics.add(state.error)
        status = LookupStatus.COMPLETE
        if diagnostics:
            status = LookupStatus.PARTIAL if observations else LookupStatus.FAILED
        return Assessment(coordinate, status, observations, tuple(sorted(diagnostics)))
