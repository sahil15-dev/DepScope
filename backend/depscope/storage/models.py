from enum import StrEnum

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class ScanSource(StrEnum):
    UPLOAD = "upload"
    PASTE = "paste"
    SAMPLE = "sample"


class Base(DeclarativeBase):
    pass


class ScanRow(Base):
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint("format IN ('requirements','npm-lock')", name="ck_scan_format"),
        CheckConstraint("source IN ('paste','upload','sample')", name="ck_scan_source"),
        CheckConstraint(
            "(source = 'sample' AND provenance = 'offline_fixture' AND sample_id IS NOT NULL) OR "
            "(source IN ('paste','upload') AND provenance = 'live_osv' AND sample_id IS NULL)",
            name="ck_scan_provenance",
        ),
        CheckConstraint(
            "(status = 'queued' AND started_at IS NULL AND finished_at IS NULL) OR "
            "(status = 'running' AND started_at IS NOT NULL AND finished_at IS NULL) OR "
            "(status IN ('complete','partial') AND started_at IS NOT NULL "
            "AND finished_at IS NOT NULL) OR "
            "(status = 'failed' AND finished_at IS NOT NULL)",
            name="ck_scan_lifecycle",
        ),
        CheckConstraint("risk_index BETWEEN 0 AND 100", name="ck_scan_risk"),
        Index("ix_scans_requested", "requested_at", "id"),
        Index("ix_scans_provenance_requested", "provenance", "requested_at", "id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    format: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(10))
    provenance: Mapped[str] = mapped_column(String(16))
    sample_id: Mapped[str | None] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(10))
    requested_at: Mapped[str] = mapped_column(String(32))
    started_at: Mapped[str | None] = mapped_column(String(32))
    finished_at: Mapped[str | None] = mapped_column(String(32))
    observed_at: Mapped[str | None] = mapped_column(String(32))
    error_code: Mapped[str | None] = mapped_column(String(48))
    result_version: Mapped[int | None]
    lockfile_version: Mapped[int | None]
    risk_index: Mapped[int | None]
    scoring_revision: Mapped[str | None] = mapped_column(String(16))
    coverage: Mapped[dict[str, object] | None] = mapped_column(JSON(none_as_null=True))
    severity_counts: Mapped[dict[str, int] | None] = mapped_column(JSON(none_as_null=True))
    limitations: Mapped[list[str] | None] = mapped_column(JSON(none_as_null=True))


class CoordinateRow(Base):
    __tablename__ = "scanned_coordinates"
    __table_args__ = (
        UniqueConstraint("scan_id", "ecosystem", "name", "version", name="uq_coordinate_identity"),
        UniqueConstraint("scan_id", "id", name="uq_coordinate_scan_id"),
        CheckConstraint("ecosystem IN ('PyPI','npm')", name="ck_coordinate_ecosystem"),
        CheckConstraint("status IN ('complete','partial','failed')", name="ck_coordinate_lookup"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    ecosystem: Mapped[str] = mapped_column(String(8))
    name: Mapped[str] = mapped_column(String(214))
    version: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(10))
    diagnostics: Mapped[list[str]] = mapped_column(JSON)


class OccurrenceRow(Base):
    __tablename__ = "dependency_occurrences"
    __table_args__ = (
        ForeignKeyConstraint(
            ("scan_id", "coordinate_id"),
            ("scanned_coordinates.scan_id", "scanned_coordinates.id"),
            name="fk_occurrence_coordinate_scan",
        ),
    )

    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), primary_key=True)
    position: Mapped[int] = mapped_column(primary_key=True)
    coordinate_id: Mapped[int | None]
    payload: Mapped[dict[str, object]] = mapped_column(JSON)


class AdvisoryRow(Base):
    __tablename__ = "advisory_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "provenance", "advisory_id", "level", "content_hash", name="uq_advisory_snapshot"
        ),
        CheckConstraint("level IN ('hydrated','discovery_only')", name="ck_advisory_level"),
        CheckConstraint(
            "provenance IN ('live_osv','offline_fixture')", name="ck_advisory_provenance"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    provenance: Mapped[str] = mapped_column(String(16))
    advisory_id: Mapped[str] = mapped_column(String(128))
    level: Mapped[str] = mapped_column(String(16))
    content_hash: Mapped[str] = mapped_column(String(64))
    captured_at: Mapped[str] = mapped_column(String(32))
    payload: Mapped[dict[str, object]] = mapped_column(JSON)


class ObservationRow(Base):
    __tablename__ = "advisory_observations"
    __table_args__ = (Index("ix_observations_snapshot", "snapshot_id"),)

    coordinate_id: Mapped[int] = mapped_column(
        ForeignKey("scanned_coordinates.id"), primary_key=True
    )
    advisory_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("advisory_snapshots.id"))
    discovery: Mapped[dict[str, object]] = mapped_column(JSON)
    error_code: Mapped[str | None] = mapped_column(String(48))


class FindingRow(Base):
    __tablename__ = "findings"
    __table_args__ = (
        ForeignKeyConstraint(
            ("scan_id", "coordinate_id"),
            ("scanned_coordinates.scan_id", "scanned_coordinates.id"),
            name="fk_finding_coordinate_scan",
        ),
        UniqueConstraint("coordinate_id", "advisory_id", name="uq_finding_identity"),
        UniqueConstraint("scan_id", "position", name="uq_finding_position"),
        UniqueConstraint("coordinate_id", "id", name="uq_finding_coordinate_id"),
        CheckConstraint(
            "severity IN ('critical','high','medium','low','none','unknown')",
            name="ck_finding_severity",
        ),
        Index("ix_findings_scan_severity", "scan_id", "severity", "position"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(36))
    coordinate_id: Mapped[int]
    position: Mapped[int]
    advisory_id: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(8))
    fix_available: Mapped[bool] = mapped_column(
        Boolean(create_constraint=True, name="ck_finding_fix_available")
    )
    payload: Mapped[dict[str, object]] = mapped_column(JSON)


class FindingAdvisoryRow(Base):
    __tablename__ = "finding_advisories"
    __table_args__ = (
        ForeignKeyConstraint(
            ("coordinate_id", "finding_id"),
            ("findings.coordinate_id", "findings.id"),
            name="fk_link_finding_coordinate",
        ),
        ForeignKeyConstraint(
            ("coordinate_id", "advisory_id"),
            ("advisory_observations.coordinate_id", "advisory_observations.advisory_id"),
            name="fk_link_observation",
        ),
        Index("ix_finding_links_observation", "coordinate_id", "advisory_id"),
    )

    finding_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    advisory_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    coordinate_id: Mapped[int]
