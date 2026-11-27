from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel

from ..models import Advisory, Coordinate, Ecosystem, LookupStatus, Occurrence, Severity
from .views import AssessmentView, FindingView, Page, ScanSummary


class GroupSort(StrEnum):
    PRIORITY = "priority"
    PACKAGE = "package"
    FINDINGS = "findings"


class PackageGroup(BaseModel):
    coordinate: Coordinate
    status: LookupStatus
    finding_count: int
    fixable_count: int
    severity_counts: dict[Severity, int]
    highest_severity: Severity


class PackagePage(Page[PackageGroup]):
    finding_count: int
    fixable_count: int


class CandidateUpgrade(BaseModel):
    version: str
    advisory_ids: list[str]
    evidence: Literal["insufficient_evidence", "known_findings", "no_known_findings"]
    scan_id: str | None = None
    observed_at: datetime | None = None
    finding_count: int | None = None
    lookup_status: LookupStatus | None = None


class ReportGroup(PackageGroup):
    findings: list[FindingView]


class ScanReport(BaseModel):
    schema_version: Literal[1] = 1
    scan: ScanSummary
    packages: list[ReportGroup]
    dependencies: list[Occurrence]
    assessments: list[AssessmentView]
    advisories: dict[str, Advisory]


class PackageIdentity(BaseModel):
    ecosystem: Ecosystem
    name: str


class DependencyChange(BaseModel):
    package: PackageIdentity
    kind: Literal["added", "removed", "changed"]
    before_versions: list[str]
    after_versions: list[str]
    before_unresolved: int
    after_unresolved: int


class FindingChange(BaseModel):
    package: PackageIdentity
    advisory_ids: list[str]
    kind: Literal["newly_detected", "no_longer_detected", "unchanged"]
    before_versions: list[str]
    after_versions: list[str]
    before_severity: Severity | None
    after_severity: Severity | None
    context: Literal["observed", "incomplete_coverage", "package_absent", "versions_changed"]


class ScanComparison(BaseModel):
    baseline: ScanSummary
    target: ScanSummary
    risk_delta: int | None
    dependencies: list[DependencyChange]
    findings: list[FindingChange]
