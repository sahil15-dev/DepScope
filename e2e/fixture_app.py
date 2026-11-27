from collections.abc import Iterable

from depscope.demo import FixtureProvider
from depscope.models import Assessment, Coordinate, Provenance
from depscope.service.web import create_web_app
from fastapi import FastAPI


class MockLiveProvider:
    """Exercise live submission routes without sending any data to OSV."""

    provenance = Provenance.LIVE_OSV

    def __init__(self) -> None:
        self._fixture = FixtureProvider.bundled()

    async def lookup(self, coordinates: Iterable[Coordinate]) -> tuple[Assessment, ...]:
        return await self._fixture.lookup(coordinates)


def create_test_app() -> FastAPI:
    return create_web_app(live_provider=MockLiveProvider())
