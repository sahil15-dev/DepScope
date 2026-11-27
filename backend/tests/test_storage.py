import asyncio
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from depscope.demo import FixtureProvider
from depscope.models import ManifestFormat, Provenance, ScanResult
from depscope.scanner import Scanner
from depscope.storage.database import database_path, database_ready, sqlite_engine, worker_lock
from depscope.storage.models import (
    AdvisoryRow,
    CoordinateRow,
    FindingRow,
    ObservationRow,
    OccurrenceRow,
    ScanSource,
    ScanStatus,
)
from depscope.storage.repository import Pagination, ScanInput, ScanRepository, TransitionConflict
from sqlalchemy import Engine, func, insert, inspect, select, text
from sqlalchemy.exc import IntegrityError

SAMPLE = ScanInput(
    ManifestFormat.REQUIREMENTS,
    ScanSource.SAMPLE,
    Provenance.OFFLINE_FIXTURE,
    "python-vulnerable",
)


def migrate(engine: Engine, *, check: bool = False) -> None:
    config = Config("alembic.ini")
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
        if check:
            command.check(config)


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[Engine]:
    engine = sqlite_engine(tmp_path / "scan.sqlite3")
    try:
        migrate(engine)
        yield engine
    finally:
        engine.dispose()


def example_result() -> ScanResult:
    provider = FixtureProvider.bundled()
    return asyncio.run(
        Scanner(provider).scan(b"Jinja2==3.1.2\nalpha>=1", ManifestFormat.REQUIREMENTS)
    )


def test_empty_upgrade_and_schema_head(tmp_path: Path) -> None:
    engine = sqlite_engine(tmp_path / "fresh.sqlite3")
    assert not database_ready(engine)
    migrate(engine, check=True)
    migrate(engine)
    assert database_ready(engine)
    inspector = inspect(engine)
    assert {
        "alembic_version",
        "scans",
        "dependency_occurrences",
        "scanned_coordinates",
        "advisory_snapshots",
        "advisory_observations",
        "findings",
        "finding_advisories",
    } == set(inspector.get_table_names())
    with engine.connect() as connection:
        assert connection.scalar(text("PRAGMA foreign_keys")) == 1
    engine.dispose()


def test_storage_rollback_and_invalid_state_transition(engine: Engine) -> None:
    repository = ScanRepository(engine)
    item = repository.create(SAMPLE)
    result = example_result()
    with pytest.raises(TransitionConflict):
        repository.finish(item.id, result)
    repository.start(item.id)
    with pytest.raises(TransitionConflict):
        repository.start(item.id)
    detached = replace(result.findings[0], observed_ids=("TEST-MISSING-OBSERVATION",))
    with pytest.raises(IntegrityError):
        repository.finish(item.id, replace(result, findings=(detached,)))
    detail = repository.detail(item.id, Pagination())
    assert detail is not None
    assert detail.scan.status is ScanStatus.RUNNING
    assert detail.scan.risk_index is None and detail.scan.finished_at is None
    for table in (CoordinateRow, OccurrenceRow, AdvisoryRow, ObservationRow, FindingRow):
        with engine.connect() as connection:
            assert connection.scalar(select(func.count()).select_from(table)) == 0
    assert repository.fail(item.id, "storage_failure")
    assert not repository.fail(item.id, "interrupted")
    with pytest.raises(TransitionConflict):
        repository.finish(item.id, result)


def test_snapshots_are_content_addressed_and_keep_older_evidence(engine: Engine) -> None:
    repository = ScanRepository(engine)
    first, second, updated = (repository.create(SAMPLE) for _ in range(3))
    result = example_result()
    assessment = result.assessments[0]
    observation = assessment.observations[0]
    advisory = observation.advisory
    assert advisory is not None
    amended = replace(
        assessment,
        observations=(
            replace(observation, advisory=replace(advisory, summary="Changed public summary")),
        ),
    )
    for scan in (first, second, updated):
        repository.start(scan.id)
        repository.finish(
            scan.id, replace(result, assessments=(amended,)) if scan is updated else result
        )
    with engine.connect() as connection:
        assert connection.scalar(select(func.count()).select_from(AdvisoryRow)) == 2
        summaries = (
            connection.execute(select(AdvisoryRow.payload).order_by(AdvisoryRow.id)).scalars().all()
        )
    assert [item["summary"] for item in summaries] == [advisory.summary, "Changed public summary"]
    assert repository.reconcile() == 0


def test_database_rejects_cross_scan_occurrence_link(engine: Engine) -> None:
    repository = ScanRepository(engine)
    a = repository.create(SAMPLE)
    b = repository.create(SAMPLE)
    with engine.begin() as connection:
        coordinate = connection.scalar(
            insert(CoordinateRow)
            .values(
                scan_id=a.id,
                ecosystem="PyPI",
                name="alpha",
                version="1",
                status="complete",
                diagnostics=[],
            )
            .returning(CoordinateRow.id)
        )
    assert coordinate is not None
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            insert(OccurrenceRow).values(
                scan_id=b.id,
                position=0,
                coordinate_id=coordinate,
                payload={},
            )
        )


def test_database_path_and_worker_ownership(tmp_path: Path) -> None:
    path = database_path(tmp_path / "private.sqlite3")
    with pytest.raises(ValueError):
        database_path(tmp_path / "missing_suffix")
    with (
        worker_lock(path),
        pytest.raises(RuntimeError, match="Another DepScope worker"),
        worker_lock(path),
    ):
        pytest.fail("A second worker cannot own the same database")
    with worker_lock(path):
        assert path.with_name(path.name + ".worker.lock").is_file()
