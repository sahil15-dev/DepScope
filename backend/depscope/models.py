from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class Ecosystem(StrEnum):
    PYPI = "PyPI"
    NPM = "npm"


class ManifestFormat(StrEnum):
    REQUIREMENTS = "requirements"
    NPM_LOCK = "npm-lock"


class Resolution(StrEnum):
    DECLARED_PIN = "declared_pin"
    LOCKED = "locked"
    RANGE = "range"
    UNPINNED = "unpinned"
    UNRESOLVED = "unresolved"
    INVALID = "invalid"


class Directness(StrEnum):
    DECLARED = "declared"
    DIRECT = "direct"
    TRANSITIVE = "transitive"
    UNKNOWN = "unknown"


class Provenance(StrEnum):
    LIVE_OSV = "live_osv"
    OFFLINE_FIXTURE = "offline_fixture"


class LookupStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True, order=True)
class Coordinate:
    ecosystem: Ecosystem
    name: str
    version: str


@dataclass(frozen=True, slots=True)
class Occurrence:
    ecosystem: Ecosystem
    resolution: Resolution
    directness: Directness
    name: str | None = None
    coordinate: Coordinate | None = None
    constraint: str | None = None
    line: int | None = None
    dependency_path: str | None = None
    entry_number: int | None = None
    extras: tuple[str, ...] = ()
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class Manifest:
    format: ManifestFormat
    occurrences: tuple[Occurrence, ...]
    lockfile_version: int | None = None

    @property
    def coordinates(self) -> tuple[Coordinate, ...]:
        return tuple(sorted({o.coordinate for o in self.occurrences if o.coordinate is not None}))


@dataclass(frozen=True, slots=True)
class SeverityEvidence:
    scheme: str
    source: str
    severity: Severity
    vector: str | None = None
    score: float | None = None
    label: str | None = None
    score_basis: str | None = None
    upstream_source: str | None = None


@dataclass(frozen=True, slots=True)
class Reference:
    kind: str
    url: str


@dataclass(frozen=True, slots=True)
class RangeEvent:
    kind: str
    version: str


@dataclass(frozen=True, slots=True)
class AffectedRange:
    kind: str
    events: tuple[RangeEvent, ...]
    repository: str | None = None


@dataclass(frozen=True, slots=True)
class AffectedPackage:
    ecosystem: str | None
    name: str | None
    versions: tuple[str, ...]
    ranges: tuple[AffectedRange, ...]
    severity: tuple[SeverityEvidence, ...]


@dataclass(frozen=True, slots=True)
class Advisory:
    id: str
    modified: datetime
    published: datetime | None
    withdrawn: datetime | None
    summary: str | None
    aliases: tuple[str, ...]
    affected: tuple[AffectedPackage, ...]
    severity: tuple[SeverityEvidence, ...]
    references: tuple[Reference, ...]


@dataclass(frozen=True, slots=True)
class Discovery:
    id: str
    modified: datetime | None


@dataclass(frozen=True, slots=True)
class Observation:
    discovery: Discovery
    advisory: Advisory | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class Assessment:
    coordinate: Coordinate
    status: LookupStatus
    observations: tuple[Observation, ...] = ()
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FixEvidence:
    advisory_id: str
    version: str
    introduced: str
    range_type: str


@dataclass(frozen=True, slots=True)
class Priority:
    severity: Severity
    severity_advisory_id: str | None
    severity_evidence: SeverityEvidence | None
    fix_available: bool
    reason: str


@dataclass(frozen=True, slots=True)
class Finding:
    coordinate: Coordinate
    advisory_id: str
    aliases: tuple[str, ...]
    observed_ids: tuple[str, ...]
    evidence_level: str
    fixes: tuple[FixEvidence, ...]
    priority: Priority


@dataclass(frozen=True, slots=True)
class Coverage:
    occurrences: int
    unresolved_occurrences: int
    exact_coordinates: int
    assessed_coordinates: int
    partial_coordinates: int
    failed_coordinates: int
    coordinates_with_findings: int


@dataclass(frozen=True, slots=True)
class Risk:
    index: int | None
    severity_counts: dict[Severity, int]
    revision: str = "1"


@dataclass(frozen=True, slots=True)
class ScanResult:
    observed_at: datetime
    provenance: Provenance
    status: LookupStatus
    manifest: Manifest
    coverage: Coverage
    assessments: tuple[Assessment, ...]
    findings: tuple[Finding, ...]
    risk: Risk
    limitations: tuple[str, ...]
    schema_version: int = 1
