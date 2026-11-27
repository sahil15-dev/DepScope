from collections import defaultdict
from dataclasses import dataclass, field
from typing import Literal

from ..models import Ecosystem, Finding, LookupStatus, Severity
from ..scoring import SEVERITY_RANK
from .analysis_views import (
    DependencyChange,
    FindingChange,
    PackageIdentity,
    ScanComparison,
    ScanReport,
)

type Identity = tuple[Ecosystem, str]


@dataclass
class _Inventory:
    versions: dict[str, LookupStatus] = field(default_factory=dict)
    unresolved: int = 0


def _inventory(report: ScanReport) -> dict[Identity, _Inventory]:
    inventory: dict[Identity, _Inventory] = defaultdict(_Inventory)
    for item in report.assessments:
        key = (item.coordinate.ecosystem, item.coordinate.name)
        inventory[key].versions[item.coordinate.version] = item.status
    for occurrence in report.dependencies:
        if occurrence.name is not None and occurrence.coordinate is None:
            inventory[occurrence.ecosystem, occurrence.name].unresolved += 1
    return inventory


def _components(items: list[tuple[int, Finding]]) -> list[list[tuple[int, Finding]]]:
    parents = list(range(len(items)))
    identities: dict[str, int] = {}

    def root(index: int) -> int:
        while index != parents[index]:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    for index, (_, finding) in enumerate(items):
        for token in (finding.advisory_id, *finding.aliases, *finding.observed_ids):
            previous = identities.setdefault(token, index)
            parents[root(previous)] = root(index)
    groups: dict[int, list[tuple[int, Finding]]] = defaultdict(list)
    for index, item in enumerate(items):
        groups[root(index)].append(item)
    return list(groups.values())


def _severity(items: list[Finding]) -> Severity | None:
    return max(
        (item.priority.severity for item in items), key=SEVERITY_RANK.__getitem__, default=None
    )


def _context(
    missing: _Inventory | None,
    versions: list[str],
    incomplete_inventory: bool,
) -> Literal["observed", "incomplete_coverage", "package_absent", "versions_changed"]:
    if incomplete_inventory:
        return "incomplete_coverage"
    if missing is None:
        return "package_absent"
    if missing.unresolved or any(
        status != LookupStatus.COMPLETE for status in missing.versions.values()
    ):
        return "incomplete_coverage"
    if not set(versions).issubset(missing.versions):
        return "versions_changed"
    return "observed"


def compare_reports(baseline: ScanReport, target: ScanReport) -> ScanComparison:
    before_inventory = _inventory(baseline)
    after_inventory = _inventory(target)
    before_incomplete = baseline.scan.coverage is None or any(
        item.name is None for item in baseline.dependencies
    )
    after_incomplete = target.scan.coverage is None or any(
        item.name is None for item in target.dependencies
    )
    dependencies = []
    for key in sorted(before_inventory.keys() | after_inventory.keys()):
        before = before_inventory.get(key, _Inventory())
        after = after_inventory.get(key, _Inventory())
        before_versions, after_versions = sorted(before.versions), sorted(after.versions)
        if before_versions == after_versions and before.unresolved == after.unresolved:
            continue
        dependencies.append(
            DependencyChange(
                package=PackageIdentity(ecosystem=key[0], name=key[1]),
                kind="added"
                if key not in before_inventory
                else "removed"
                if key not in after_inventory
                else "changed",
                before_versions=before_versions,
                after_versions=after_versions,
                before_unresolved=before.unresolved,
                after_unresolved=after.unresolved,
            )
        )

    findings_by_package: dict[Identity, list[tuple[int, Finding]]] = defaultdict(list)
    for side, report in enumerate((baseline, target)):
        for group in report.packages:
            key = (group.coordinate.ecosystem, group.coordinate.name)
            findings_by_package[key].extend((side, entry.finding) for entry in group.findings)

    changes = []
    for key, items in sorted(findings_by_package.items()):
        for cluster in _components(items):
            old = [entry for side, entry in cluster if side == 0]
            new = [entry for side, entry in cluster if side == 1]
            old_versions = sorted({item.coordinate.version for item in old})
            new_versions = sorted({item.coordinate.version for item in new})
            if not old:
                kind: Literal["newly_detected", "no_longer_detected", "unchanged"] = (
                    "newly_detected"
                )
                context = _context(before_inventory.get(key), new_versions, before_incomplete)
            elif not new:
                kind = "no_longer_detected"
                context = _context(after_inventory.get(key), old_versions, after_incomplete)
            else:
                kind = "unchanged"
                if old_versions != new_versions:
                    context = "versions_changed"
                elif "incomplete_coverage" in (
                    _context(before_inventory[key], old_versions, before_incomplete),
                    _context(after_inventory[key], new_versions, after_incomplete),
                ):
                    context = "incomplete_coverage"
                else:
                    context = "observed"
            changes.append(
                FindingChange(
                    package=PackageIdentity(ecosystem=key[0], name=key[1]),
                    advisory_ids=sorted(
                        {
                            token
                            for _, item in cluster
                            for token in (item.advisory_id, *item.aliases)
                        }
                    ),
                    kind=kind,
                    before_versions=old_versions,
                    after_versions=new_versions,
                    before_severity=_severity(old),
                    after_severity=_severity(new),
                    context=context,
                )
            )
    old_risk, new_risk = baseline.scan.risk_index, target.scan.risk_index
    comparable_risk = baseline.scan.scoring_revision == target.scan.scoring_revision
    return ScanComparison(
        baseline=baseline.scan,
        target=target.scan,
        dependencies=dependencies,
        findings=sorted(
            changes, key=lambda item: (item.package.ecosystem, item.package.name, item.advisory_ids)
        ),
        risk_delta=new_risk - old_risk
        if comparable_risk and old_risk is not None and new_risk is not None
        else None,
    )
