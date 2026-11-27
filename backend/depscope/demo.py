from collections.abc import Iterable
from importlib.resources import files
from importlib.resources.abc import Traversable
from typing import Self

import httpx

from ._json import InvalidPayload, array_value, decode_json, object_value
from .errors import ScanError
from .models import Assessment, Coordinate, LookupStatus, Provenance
from .osv import OSVClient, OSVConfig


class FixtureProvider:
    """Exercise the OSV gateway with bundled, explicitly scoped responses."""

    provenance = Provenance.OFFLINE_FIXTURE

    def __init__(self, fixture: Traversable) -> None:
        try:
            with fixture.open("rb") as file:
                content = file.read(1_000_001)
            if len(content) > 1_000_000:
                raise InvalidPayload("fixture_too_large")
            root = object_value(decode_json(content))
            self._queries = object_value(root.get("queries"))
            self._advisories = object_value(root.get("advisories"))
        except (InvalidPayload, OSError) as exc:
            raise ScanError(
                "invalid_fixture", "The bundled OSV fixture could not be loaded."
            ) from exc

    @classmethod
    def bundled(cls) -> Self:
        return cls(files("depscope").joinpath("fixtures", "osv.json"))

    def _respond(self, request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/v1/querybatch":
            request_body = object_value(decode_json(request.content))
            rows = []
            for query in array_value(request_body["queries"]):
                entry = object_value(query)
                package = object_value(entry["package"])
                key = f"{package['ecosystem']}:{package['name']}:{entry['version']}"
                rows.append(self._queries[key])
            return httpx.Response(200, json={"results": rows})
        if request.method == "GET" and request.url.path.startswith("/v1/vulns/"):
            identifier = request.url.path.rsplit("/", 1)[-1]
            if identifier in self._advisories:
                return httpx.Response(200, json=self._advisories[identifier])
        return httpx.Response(404)

    async def lookup(self, coordinates: Iterable[Coordinate]) -> tuple[Assessment, ...]:
        covered: list[Coordinate] = []
        missing: list[Assessment] = []
        for coordinate in coordinates:
            if f"{coordinate.ecosystem}:{coordinate.name}:{coordinate.version}" in self._queries:
                covered.append(coordinate)
            else:
                missing.append(
                    Assessment(
                        coordinate,
                        LookupStatus.FAILED,
                        diagnostics=("fixture_coordinate_unavailable",),
                    )
                )
        async with OSVClient(
            config=OSVConfig(request_interval=0),
            transport=httpx.MockTransport(self._respond),
            provenance=self.provenance,
        ) as gateway:
            return (*await gateway.lookup(covered), *missing)
