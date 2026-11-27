from collections.abc import Iterable

from .models import Coordinate, Finding, Risk, Severity

SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.NONE: 1,
    Severity.UNKNOWN: 0,
}


def priority_order(finding: Finding) -> tuple[int, bool, Coordinate, str]:
    return (
        -SEVERITY_RANK[finding.priority.severity],
        not finding.priority.fix_available,
        finding.coordinate,
        finding.advisory_id,
    )


def summarize_risk(findings: Iterable[Finding], assessed: int) -> Risk:
    counts = dict.fromkeys(Severity, 0)
    for finding in findings:
        counts[finding.priority.severity] += 1
    total = sum(counts.values())
    if assessed == 0 or (total and total == counts[Severity.UNKNOWN]):
        return Risk(None, counts)
    index = min(
        100,
        20 * counts[Severity.CRITICAL]
        + 10 * counts[Severity.HIGH]
        + 4 * counts[Severity.MEDIUM]
        + counts[Severity.LOW],
    )
    return Risk(index, counts)
