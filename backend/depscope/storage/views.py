from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from ..models import (
    Advisory,
    Coordinate,
    Coverage,
    Discovery,
    Finding,
    LookupStatus,
    ManifestFormat,
    Occurrence,
    Provenance,
)
from .models import ScanSource, ScanStatus


class ScanSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    format: ManifestFormat
    source: ScanSource
    provenance: Provenance
    sample_id: str | None
    status: ScanStatus
    requested_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    observed_at: datetime | None
    error_code: str | None
    result_version: int | None
    lockfile_version: int | None
    risk_index: int | None
    scoring_revision: str | None
    coverage: Coverage | None
    severity_counts: dict[str, int] | None
    limitations: list[str] | None


class Page[T](BaseModel):
    items: list[T]
    page: int
    page_size: int
    total: int


class ObservationView(BaseModel):
    discovery: Discovery
    evidence_level: str
    error_code: str | None


class AssessmentView(BaseModel):
    coordinate: Coordinate
    status: LookupStatus
    diagnostics: list[str]
    observations: list[ObservationView]


class ScanDetail(BaseModel):
    scan: ScanSummary
    dependencies: Page[Occurrence]
    assessments: Page[AssessmentView]


class FindingView(BaseModel):
    finding: Finding
    observations: list[ObservationView]


class FindingsPage(Page[FindingView]):
    advisories: dict[str, Advisory]


class Overview(BaseModel):
    provenance: Provenance | None
    status_counts: dict[ScanStatus, int]
    recent_scans: list[ScanSummary]
    latest_result: ScanSummary | None
    risk_trend: list[ScanSummary]


class ScanSort(StrEnum):
    NEWEST = "newest"
    OLDEST = "oldest"
    RISK = "risk"


class FindingSort(StrEnum):
    PRIORITY = "priority"
    PACKAGE = "package"
