from dataclasses import dataclass, replace
from functools import cmp_to_key

from packaging.version import Version as PythonVersion
from semver import Version as NpmVersion

from .identity import ordered_version, package_name
from .models import (
    Advisory,
    AffectedPackage,
    AffectedRange,
    Assessment,
    Coordinate,
    Ecosystem,
    Finding,
    FixEvidence,
    LookupStatus,
    Observation,
    Priority,
    RangeEvent,
    Severity,
    SeverityEvidence,
)
from .scoring import SEVERITY_RANK

type _Version = PythonVersion | NpmVersion


def _compare(left: _Version, right: _Version) -> int:
    if isinstance(left, PythonVersion) and isinstance(right, PythonVersion):
        return (left > right) - (left < right)
    if isinstance(left, NpmVersion) and isinstance(right, NpmVersion):
        return left.compare(right)
    raise TypeError("Version comparisons require a shared ecosystem")


@dataclass(frozen=True, slots=True)
class _Point:
    event: RangeEvent
    version: _Version | None


def _point_order(left: _Point, right: _Point) -> int:
    if left.version is None or right.version is None:
        return (left.version is not None) - (right.version is not None)
    return _compare(left.version, right.version)


def _event_order(left: _Point, right: _Point) -> int:
    return _point_order(left, right) or (
        (right.event.kind == "introduced") - (left.event.kind == "introduced")
    )


@dataclass(frozen=True, slots=True)
class _Interval:
    start: _Point
    end: _Point | None

    def contains(self, version: _Version) -> bool:
        if self.start.version is not None and _compare(version, self.start.version) < 0:
            return False
        if self.end is None:
            return True
        assert self.end.version is not None
        comparison = _compare(version, self.end.version)
        return comparison < 0 or (comparison == 0 and self.end.event.kind == "last_affected")


@dataclass(frozen=True, slots=True)
class _Timeline:
    range_type: str
    intervals: tuple[_Interval, ...]
    limits: tuple[_Version, ...]

    def covers(self, version: _Version) -> bool:
        return not self.limits or any(_compare(version, limit) < 0 for limit in self.limits)


def _timeline(ecosystem: Ecosystem, source: AffectedRange) -> _Timeline | None:
    supported = {"ECOSYSTEM", "SEMVER"} if ecosystem is Ecosystem.NPM else {"ECOSYSTEM"}
    if source.kind not in supported:
        return None
    points: list[_Point] = []
    limits: list[_Version] = []
    infinite_limit = False
    terminators: set[str] = set()
    for event in source.events:
        if event.kind == "limit" and event.version == "*":
            infinite_limit = True
            continue
        if event.kind == "introduced" and event.version == "0":
            points.append(_Point(event, None))
            continue
        value = ordered_version(ecosystem, event.version)
        if value is None:
            return None
        if event.kind == "limit":
            limits.append(value)
        elif event.kind in ("introduced", "fixed", "last_affected"):
            points.append(_Point(event, value))
            if event.kind != "introduced":
                terminators.add(event.kind)
        else:
            return None
    if not points or len(terminators) > 1:
        return None
    points.sort(key=cmp_to_key(_event_order))
    intervals: list[_Interval] = []
    start: _Point | None = None
    for index, point in enumerate(points):
        # An introduction and inclusive last-affected boundary at the same version is valid.
        if (
            index
            and _point_order(points[index - 1], point) == 0
            and (points[index - 1] is not start or point.event.kind != "last_affected")
        ):
            return None
        if point.event.kind == "introduced" and start is None:
            start = point
        elif point.event.kind != "introduced" and start is not None:
            intervals.append(_Interval(start, point))
            start = None
        else:
            return None
    if start is not None:
        intervals.append(_Interval(start, None))
    return _Timeline(source.kind, tuple(intervals), () if infinite_limit else tuple(limits))


@dataclass(frozen=True, slots=True)
class _Scope:
    advisory_id: str
    explicit_versions: tuple[_Version, ...]
    timelines: tuple[_Timeline, ...]
    severity: tuple[SeverityEvidence, ...]

    def includes(self, version: _Version) -> bool:
        return any(_compare(version, item) == 0 for item in self.explicit_versions) or any(
            timeline.covers(version)
            and any(interval.contains(version) for interval in timeline.intervals)
            for timeline in self.timelines
        )

    def fixed(self, version: _Version) -> tuple[tuple[FixEvidence, _Version], ...]:
        items: list[tuple[FixEvidence, _Version]] = []
        for timeline in self.timelines:
            if not timeline.covers(version):
                continue
            for interval in timeline.intervals:
                end = interval.end
                if end is None or end.event.kind != "fixed" or not interval.contains(version):
                    continue
                assert end.version is not None
                if timeline.limits and all(
                    _compare(end.version, limit) > 0 for limit in timeline.limits
                ):
                    continue
                items.append(
                    (
                        FixEvidence(
                            self.advisory_id,
                            end.event.version,
                            interval.start.event.version,
                            timeline.range_type,
                        ),
                        end.version,
                    )
                )
        return tuple(items)


def _scope(ecosystem: Ecosystem, advisory_id: str, affected: AffectedPackage) -> _Scope:
    return _Scope(
        advisory_id,
        tuple(
            value
            for item in affected.versions
            if (value := ordered_version(ecosystem, item)) is not None
        ),
        tuple(
            timeline
            for source in affected.ranges
            if (timeline := _timeline(ecosystem, source)) is not None
        ),
        affected.severity,
    )


@dataclass(frozen=True, slots=True)
class _Candidate:
    id: str
    aliases: tuple[str, ...] = ()
    advisory: Advisory | None = None
    severity: tuple[SeverityEvidence, ...] = ()
    scopes: tuple[_Scope, ...] = ()
    fixes: tuple[tuple[FixEvidence, _Version], ...] = ()


def _candidate(coordinate: Coordinate, observation: Observation) -> _Candidate | None:
    advisory = observation.advisory
    if advisory is None:
        return _Candidate(observation.discovery.id)
    if advisory.withdrawn:
        return None
    version = ordered_version(coordinate.ecosystem, coordinate.version)
    assert version is not None
    scopes = [
        _scope(coordinate.ecosystem, advisory.id, item)
        for item in advisory.affected
        if item.ecosystem == coordinate.ecosystem
        and item.name is not None
        and package_name(coordinate.ecosystem, item.name) == coordinate.name
    ]
    matched = [item for item in scopes if item.includes(version)]
    if not matched:
        return _Candidate(observation.discovery.id)
    rated = tuple(
        evidence
        for item in matched
        for evidence in item.severity
        if evidence.severity is not Severity.UNKNOWN
    )
    fixes = tuple(fix for item in matched for fix in item.fixed(version))
    return _Candidate(
        advisory.id, advisory.aliases, advisory, rated or advisory.severity, tuple(scopes), fixes
    )


def _groups(candidates: list[_Candidate]) -> list[list[_Candidate]]:
    groups: list[tuple[set[str], list[_Candidate]]] = []
    for candidate in candidates:
        ids = {candidate.id, *candidate.aliases}
        members = [candidate]
        remaining: list[tuple[set[str], list[_Candidate]]] = []
        for other_ids, other_members in groups:
            if ids.intersection(other_ids):
                ids.update(other_ids)
                members.extend(other_members)
            else:
                remaining.append((other_ids, other_members))
        groups = [*remaining, (ids, members)]
    return [members for _, members in groups]


def _evidence_order(item: tuple[str, SeverityEvidence]) -> tuple[int, bool, float, str, str, str]:
    advisory_id, evidence = item
    return (
        -SEVERITY_RANK[evidence.severity],
        evidence.score is None,
        -(evidence.score or 0),
        advisory_id,
        evidence.source,
        evidence.vector or evidence.label or "",
    )


def _finding(coordinate: Coordinate, group: list[_Candidate]) -> Finding:
    observed = tuple(sorted(item.id for item in group))
    supported = sorted(item.id for item in group if item.advisory is not None)
    representative = (supported or list(observed))[0]
    aliases = tuple(
        sorted(
            ({alias for item in group for alias in item.aliases} | set(observed)) - {representative}
        )
    )
    scopes = [scope for item in group for scope in item.scopes]
    fixes = tuple(
        sorted(
            {
                fix
                for item in group
                for fix, version in item.fixes
                if not any(scope.includes(version) for scope in scopes)
            },
            key=lambda item: (
                item.version,
                item.advisory_id,
                item.introduced,
                item.range_type,
            ),
        )
    )
    ranked = sorted(
        (
            (item.id, evidence)
            for item in group
            for evidence in item.severity
            if evidence.severity is not Severity.UNKNOWN
        ),
        key=_evidence_order,
    )
    advisory_id, evidence = ranked[0] if ranked else (None, None)
    severity = evidence.severity if evidence else Severity.UNKNOWN
    reason = "manual_severity_review"
    if evidence:
        reason = "severity_with_advisory_fix" if fixes else "severity_without_advisory_fix"
    return Finding(
        coordinate,
        representative,
        aliases,
        observed,
        "hydrated" if supported else "discovery_only",
        fixes,
        Priority(severity, advisory_id, evidence, bool(fixes), reason),
    )


def match_assessment(assessment: Assessment) -> tuple[Assessment, tuple[Finding, ...]]:
    candidates: list[_Candidate] = []
    diagnostics = set(assessment.diagnostics)
    status = assessment.status
    for observation in assessment.observations:
        match = _candidate(assessment.coordinate, observation)
        if match is None:
            diagnostics.add("withdrawn_advisory_ignored")
            continue
        if match.advisory is None:
            diagnostics.add(observation.error or "advisory_scope_unconfirmed")
            status = LookupStatus.PARTIAL
        candidates.append(match)
    return (
        replace(assessment, diagnostics=tuple(sorted(diagnostics)), status=status),
        tuple(_finding(assessment.coordinate, group) for group in _groups(candidates)),
    )
