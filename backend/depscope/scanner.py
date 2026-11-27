from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Protocol

from .matching import match_assessment
from .models import (
    Assessment,
    Coordinate,
    Coverage,
    LookupStatus,
    ManifestFormat,
    Provenance,
    ScanResult,
)
from .parsers import DEFAULT_PARSE_LIMITS, ParseLimits, parse_manifest
from .scoring import priority_order, summarize_risk


class AdvisoryProvider(Protocol):
    @property
    def provenance(self) -> Provenance: ...

    async def lookup(self, coordinates: Iterable[Coordinate]) -> tuple[Assessment, ...]: ...


class Scanner:
    def __init__(
        self, provider: AdvisoryProvider, *, limits: ParseLimits = DEFAULT_PARSE_LIMITS
    ) -> None:
        self._provider = provider
        self._limits = limits

    async def scan(self, content: bytes, format: ManifestFormat) -> ScanResult:
        manifest = parse_manifest(content, format, limits=self._limits)
        coordinates = manifest.coordinates
        observed_at = datetime.now(UTC)
        supplied = await self._provider.lookup(coordinates) if coordinates else ()
        by_coordinate = {item.coordinate: item for item in supplied}
        if len(by_coordinate) != len(supplied) or set(by_coordinate).difference(coordinates):
            by_coordinate = {}
        matched = [
            match_assessment(
                by_coordinate.get(key)
                or Assessment(
                    key,
                    LookupStatus.FAILED,
                    diagnostics=("uncorrelated_provider_result",),
                )
            )
            for key in coordinates
        ]
        assessments = tuple(item for item, _ in matched)
        findings = tuple(
            sorted((finding for _, matches in matched for finding in matches), key=priority_order)
        )
        assessed = sum(item.status is LookupStatus.COMPLETE for item in assessments)
        partial = sum(item.status is LookupStatus.PARTIAL for item in assessments)
        failed = len(assessments) - assessed - partial
        status = LookupStatus.COMPLETE
        if failed or partial:
            status = LookupStatus.PARTIAL if assessed or partial else LookupStatus.FAILED
        coverage = Coverage(
            len(manifest.occurrences),
            sum(item.coordinate is None for item in manifest.occurrences),
            len(coordinates),
            assessed,
            partial,
            failed,
            len({item.coordinate for item in findings}),
        )
        limitations = [
            "declared_requirements_only"
            if format is ManifestFormat.REQUIREMENTS
            else "npm_lockfile_inventory_only",
            "known_advisories_only",
            "runtime_reachability_not_assessed",
        ]
        if not coordinates:
            limitations.append("no_exact_versions")
        if coverage.unresolved_occurrences:
            limitations.append("unresolved_entries")
        if failed or partial:
            limitations.append("incomplete_advisory_coverage")
        if self._provider.provenance is Provenance.OFFLINE_FIXTURE:
            limitations.append("bundled_fixture_subset")
        return ScanResult(
            observed_at,
            self._provider.provenance,
            status,
            manifest,
            coverage,
            assessments,
            findings,
            summarize_risk(findings, assessed),
            tuple(limitations),
        )
