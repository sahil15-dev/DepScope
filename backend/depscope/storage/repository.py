import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from uuid import uuid4

from pydantic import TypeAdapter
from sqlalchemy import Engine, Select, func, select, update
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.orm import Session, sessionmaker

from ..models import (
    Advisory,
    Coordinate,
    Coverage,
    Discovery,
    Ecosystem,
    Finding,
    LookupStatus,
    ManifestFormat,
    Observation,
    Occurrence,
    Provenance,
    ScanResult,
    Severity,
)
from .models import (
    AdvisoryRow,
    CoordinateRow,
    FindingAdvisoryRow,
    FindingRow,
    ObservationRow,
    OccurrenceRow,
    ScanRow,
    ScanSource,
    ScanStatus,
)
from .views import (
    AssessmentView,
    FindingSort,
    FindingsPage,
    FindingView,
    ObservationView,
    Overview,
    Page,
    ScanDetail,
    ScanSort,
    ScanSummary,
)

_ADVISORY = TypeAdapter(Advisory)
_COVERAGE = TypeAdapter(Coverage)
_DISCOVERY = TypeAdapter(Discovery)
_FINDING = TypeAdapter(Finding)
_OCCURRENCE = TypeAdapter(Occurrence)


def _utc(value: datetime | None = None) -> str:
    return (
        (value or datetime.now(UTC))
        .astimezone(UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _json[T](adapter: TypeAdapter[T], value: T) -> dict[str, object]:
    payload: dict[str, object] = adapter.dump_python(value, mode="json")
    return payload


class TransitionConflict(RuntimeError):
    """A row is missing or is no longer in the expected state."""


@dataclass(frozen=True, slots=True)
class ScanInput:
    format: ManifestFormat
    source: ScanSource
    provenance: Provenance
    sample_id: str | None = None


@dataclass(frozen=True, slots=True)
class Pagination:
    page: int = 1
    page_size: int = 20

    def apply[T](self, statement: Select[tuple[T]]) -> Select[tuple[T]]:
        return statement.offset((self.page - 1) * self.page_size).limit(self.page_size)


class ScanRepository:
    def __init__(self, engine: Engine) -> None:
        self._sessions = sessionmaker(engine)

    def create(self, metadata: ScanInput) -> ScanSummary:
        with self._sessions.begin() as session:
            row = ScanRow(
                id=str(uuid4()),
                requested_at=_utc(),
                status=ScanStatus.QUEUED,
                format=metadata.format,
                source=metadata.source,
                provenance=metadata.provenance,
                sample_id=metadata.sample_id,
            )
            session.add(row)
            session.flush()
            return ScanSummary.model_validate(row)

    def start(self, scan_id: str) -> None:
        with self._sessions.begin() as session:
            started = session.scalar(
                update(ScanRow)
                .where(
                    ScanRow.id == scan_id,
                    ScanRow.status == ScanStatus.QUEUED,
                )
                .values(status=ScanStatus.RUNNING, started_at=_utc())
                .returning(ScanRow.id)
            )
            if started is None:
                raise TransitionConflict("Scan must be queued before it can start")

    def fail(self, scan_id: str, code: str) -> bool:
        with self._sessions.begin() as session:
            return (
                session.scalar(
                    update(ScanRow)
                    .where(
                        ScanRow.id == scan_id,
                        ScanRow.status.in_((ScanStatus.QUEUED, ScanStatus.RUNNING)),
                    )
                    .values(status=ScanStatus.FAILED, finished_at=_utc(), error_code=code)
                    .returning(ScanRow.id)
                )
                is not None
            )

    def reconcile(self) -> int:
        with self._sessions.begin() as session:
            rows = session.scalars(
                update(ScanRow)
                .where(
                    ScanRow.status.in_((ScanStatus.QUEUED, ScanStatus.RUNNING)),
                )
                .values(
                    status=ScanStatus.FAILED,
                    finished_at=_utc(),
                    error_code="interrupted",
                )
                .returning(ScanRow.id)
            ).all()
            return len(rows)

    def finish(self, scan_id: str, result: ScanResult) -> None:
        with self._sessions.begin() as session:
            finalized = session.scalar(
                update(ScanRow)
                .where(
                    ScanRow.id == scan_id,
                    ScanRow.status == ScanStatus.RUNNING,
                    ScanRow.format == result.manifest.format,
                    ScanRow.provenance == result.provenance,
                )
                .values(
                    status=result.status,
                    finished_at=_utc(),
                    observed_at=_utc(result.observed_at),
                    error_code="advisory_lookup_failed"
                    if result.status is LookupStatus.FAILED
                    else None,
                    result_version=result.schema_version,
                    lockfile_version=result.manifest.lockfile_version,
                    risk_index=result.risk.index,
                    scoring_revision=result.risk.revision,
                    coverage=_json(_COVERAGE, result.coverage),
                    severity_counts=result.risk.severity_counts,
                    limitations=list(result.limitations),
                )
                .returning(ScanRow.id)
            )
            if finalized is None:
                raise TransitionConflict("Result must match a running scan")
            self._store_result(session, scan_id, result)

    @staticmethod
    def _store_result(session: Session, scan_id: str, result: ScanResult) -> None:
        coordinates = {
            item.coordinate: CoordinateRow(
                scan_id=scan_id,
                ecosystem=item.coordinate.ecosystem,
                name=item.coordinate.name,
                version=item.coordinate.version,
                status=item.status,
                diagnostics=list(item.diagnostics),
            )
            for item in result.assessments
        }
        session.add_all(coordinates.values())
        session.flush()
        session.add_all(
            OccurrenceRow(
                scan_id=scan_id,
                position=position,
                coordinate_id=coordinates[item.coordinate].id if item.coordinate else None,
                payload=_json(_OCCURRENCE, item),
            )
            for position, item in enumerate(result.manifest.occurrences)
        )
        snapshots: dict[int, int] = {}
        for assessment in result.assessments:
            coordinate_id = coordinates[assessment.coordinate].id
            for item in assessment.observations:
                evidence = item.advisory or item.discovery
                identity = id(evidence)
                if identity not in snapshots:
                    snapshots[identity] = _snapshot(session, result.provenance, item)
                session.add(
                    ObservationRow(
                        coordinate_id=coordinate_id,
                        advisory_id=item.discovery.id,
                        snapshot_id=snapshots[identity],
                        discovery=_json(_DISCOVERY, item.discovery),
                        error_code=item.error,
                    )
                )
        rows: list[FindingRow] = []
        for position, finding in enumerate(result.findings):
            rows.append(
                FindingRow(
                    scan_id=scan_id,
                    coordinate_id=coordinates[finding.coordinate].id,
                    position=position,
                    advisory_id=finding.advisory_id,
                    severity=finding.priority.severity,
                    fix_available=finding.priority.fix_available,
                    payload=_json(_FINDING, finding),
                )
            )
        session.add_all(rows)
        session.flush()
        session.add_all(
            FindingAdvisoryRow(
                finding_id=row.id, coordinate_id=row.coordinate_id, advisory_id=identifier
            )
            for row, item in zip(rows, result.findings, strict=True)
            for identifier in item.observed_ids
        )

    def list_scans(
        self,
        pagination: Pagination,
        *,
        provenance: Provenance | None,
        status: ScanStatus | None,
        format: ManifestFormat | None,
        sort: ScanSort,
    ) -> Page[ScanSummary]:
        query = select(ScanRow)
        if provenance:
            query = query.where(ScanRow.provenance == provenance)
        if status:
            query = query.where(ScanRow.status == status)
        if format:
            query = query.where(ScanRow.format == format)
        order = (ScanRow.requested_at.desc(), ScanRow.id.desc())
        if sort is ScanSort.OLDEST:
            order = (ScanRow.requested_at.asc(), ScanRow.id.asc())
        if sort is ScanSort.RISK:
            query = query.order_by(ScanRow.risk_index.desc().nulls_last())
        with self._sessions() as session:
            total = _count(session, query)
            rows = session.scalars(pagination.apply(query.order_by(*order)))
            return Page[ScanSummary](
                items=[ScanSummary.model_validate(row) for row in rows],
                total=total,
                page=pagination.page,
                page_size=pagination.page_size,
            )

    def detail(self, scan_id: str, pagination: Pagination) -> ScanDetail | None:
        with self._sessions() as session:
            scan = session.get(ScanRow, scan_id)
            if scan is None:
                return None
            dependency_query = select(OccurrenceRow).where(OccurrenceRow.scan_id == scan_id)
            dependencies = session.scalars(
                pagination.apply(dependency_query.order_by(OccurrenceRow.position))
            )
            coordinate_query = select(CoordinateRow).where(CoordinateRow.scan_id == scan_id)
            coordinates = session.scalars(
                pagination.apply(coordinate_query.order_by(CoordinateRow.id))
            ).all()
            observations = _coordinate_observations(session, [row.id for row in coordinates])
            return ScanDetail(
                scan=ScanSummary.model_validate(scan),
                dependencies=Page[Occurrence](
                    items=[_OCCURRENCE.validate_python(row.payload) for row in dependencies],
                    total=_count(session, dependency_query),
                    page=pagination.page,
                    page_size=pagination.page_size,
                ),
                assessments=Page[AssessmentView](
                    items=[_assessment(row, observations.get(row.id, [])) for row in coordinates],
                    total=_count(session, coordinate_query),
                    page=pagination.page,
                    page_size=pagination.page_size,
                ),
            )

    def findings(
        self,
        scan_id: str,
        pagination: Pagination,
        *,
        ecosystem: Ecosystem | None,
        severity: Severity | None,
        package: str | None,
        fix_available: bool | None,
        sort: FindingSort,
    ) -> FindingsPage | None:
        with self._sessions() as session:
            if session.get(ScanRow, scan_id) is None:
                return None
            query = (
                select(FindingRow)
                .join(CoordinateRow, FindingRow.coordinate_id == CoordinateRow.id)
                .where(FindingRow.scan_id == scan_id)
            )
            if ecosystem:
                query = query.where(CoordinateRow.ecosystem == ecosystem)
            if severity:
                query = query.where(FindingRow.severity == severity)
            if package:
                query = query.where(CoordinateRow.name.contains(package, autoescape=True))
            if fix_available is not None:
                query = query.where(FindingRow.fix_available == fix_available)
            total = _count(session, query)
            if sort is FindingSort.PACKAGE:
                query = query.order_by(
                    CoordinateRow.name, CoordinateRow.ecosystem, CoordinateRow.version
                )
            rows = session.scalars(pagination.apply(query.order_by(FindingRow.position))).all()
            observations, advisories = _finding_evidence(session, [row.id for row in rows])
            return FindingsPage(
                items=[
                    FindingView(
                        finding=_FINDING.validate_python(row.payload),
                        observations=observations.get(row.id, []),
                    )
                    for row in rows
                ],
                page=pagination.page,
                page_size=pagination.page_size,
                total=total,
                advisories=advisories,
            )

    def overview(self, provenance: Provenance | None, limit: int) -> Overview:
        base = select(ScanRow)
        if provenance:
            base = base.where(ScanRow.provenance == provenance)
        ids = base.subquery()
        with self._sessions() as session:
            counts = dict.fromkeys(ScanStatus, 0)
            for status, count in session.execute(
                select(ids.c.status, func.count()).group_by(ids.c.status)
            ):
                counts[ScanStatus(status)] = count
            recent = session.scalars(
                base.order_by(ScanRow.requested_at.desc(), ScanRow.id.desc()).limit(limit)
            )
            finished = base.where(ScanRow.observed_at.is_not(None)).order_by(
                ScanRow.observed_at.desc(), ScanRow.id.desc()
            )
            trend = session.scalars(finished.limit(limit)).all()
            latest = session.scalar(
                finished.where(ScanRow.status.in_((ScanStatus.COMPLETE, ScanStatus.PARTIAL))).limit(
                    1
                )
            )
            return Overview(
                provenance=provenance,
                status_counts=counts,
                recent_scans=[ScanSummary.model_validate(row) for row in recent],
                latest_result=ScanSummary.model_validate(latest) if latest else None,
                risk_trend=[ScanSummary.model_validate(row) for row in reversed(trend)],
            )


def _count[T](session: Session, query: Select[tuple[T]]) -> int:
    return session.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0


def _snapshot(session: Session, provenance: Provenance, item: Observation) -> int:
    level = "hydrated" if item.advisory else "discovery_only"
    payload = (
        _json(_ADVISORY, item.advisory) if item.advisory else _json(_DISCOVERY, item.discovery)
    )
    fingerprint = sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    key = dict(
        provenance=provenance, advisory_id=item.discovery.id, level=level, content_hash=fingerprint
    )
    snapshot_id = session.scalar(
        insert(AdvisoryRow)
        .values(
            **key,
            captured_at=_utc(),
            payload=payload,
        )
        .on_conflict_do_nothing(index_elements=list(key))
        .returning(AdvisoryRow.id)
    )
    if snapshot_id is None:
        snapshot_id = session.execute(select(AdvisoryRow.id).filter_by(**key)).scalar_one()
    return snapshot_id


def _view(row: ObservationRow, level: str) -> ObservationView:
    return ObservationView(
        discovery=_DISCOVERY.validate_python(row.discovery),
        evidence_level=level,
        error_code=row.error_code,
    )


def _assessment(row: CoordinateRow, observations: list[ObservationView]) -> AssessmentView:
    return AssessmentView(
        coordinate=Coordinate(Ecosystem(row.ecosystem), row.name, row.version),
        status=LookupStatus(row.status),
        diagnostics=row.diagnostics,
        observations=observations,
    )


def _coordinate_observations(session: Session, ids: list[int]) -> dict[int, list[ObservationView]]:
    views: dict[int, list[ObservationView]] = defaultdict(list)
    if ids:
        query = (
            select(ObservationRow, AdvisoryRow.level)
            .join(AdvisoryRow, ObservationRow.snapshot_id == AdvisoryRow.id)
            .where(
                ObservationRow.coordinate_id.in_(ids),
            )
            .order_by(ObservationRow.coordinate_id, ObservationRow.advisory_id)
        )
        for row, level in session.execute(query):
            views[row.coordinate_id].append(_view(row, level))
    return views


def _finding_evidence(
    session: Session, ids: list[int]
) -> tuple[dict[int, list[ObservationView]], dict[str, Advisory]]:
    views: dict[int, list[ObservationView]] = defaultdict(list)
    advisories: dict[str, Advisory] = {}
    if ids:
        query = (
            select(FindingAdvisoryRow.finding_id, ObservationRow, AdvisoryRow.level)
            .select_from(FindingAdvisoryRow)
            .join(
                ObservationRow,
                (FindingAdvisoryRow.coordinate_id == ObservationRow.coordinate_id)
                & (FindingAdvisoryRow.advisory_id == ObservationRow.advisory_id),
            )
            .join(AdvisoryRow, ObservationRow.snapshot_id == AdvisoryRow.id)
            .where(FindingAdvisoryRow.finding_id.in_(ids))
            .order_by(
                FindingAdvisoryRow.finding_id,
                ObservationRow.advisory_id,
            )
        )
        snapshot_ids: set[int] = set()
        for finding_id, observation, level in session.execute(query):
            views[finding_id].append(_view(observation, level))
            if level == "hydrated":
                snapshot_ids.add(observation.snapshot_id)
        if snapshot_ids:
            for snapshot in session.scalars(
                select(AdvisoryRow).where(AdvisoryRow.id.in_(snapshot_ids)).order_by(AdvisoryRow.id)
            ):
                advisories[snapshot.advisory_id] = _ADVISORY.validate_python(snapshot.payload)
    return views, advisories
