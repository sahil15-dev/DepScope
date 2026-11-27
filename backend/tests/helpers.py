from datetime import UTC, datetime

from depscope.models import Coordinate, Ecosystem

MODIFIED = "2025-01-02T00:00:00Z"
NOW = datetime(2025, 1, 2, tzinfo=UTC)
ALPHA = Coordinate(Ecosystem.PYPI, "alpha", "1")
BETA = Coordinate(Ecosystem.PYPI, "beta", "2")


def advisory(identifier: str, name: str = "alpha", **fields: object) -> dict[str, object]:
    return {
        "id": identifier,
        "modified": MODIFIED,
        "affected": [{"package": {"name": name, "ecosystem": "PyPI"}, "versions": ["1.0"]}],
        **fields,
    }
