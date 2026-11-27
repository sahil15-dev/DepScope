import argparse
import asyncio
import os
import sys
from pathlib import Path

from .demo import FixtureProvider
from .errors import ScanError
from .models import LookupStatus, ManifestFormat, ScanResult
from .osv import OSVClient
from .parsers import ParseLimits
from .scanner import Scanner
from .serialization import to_json


def _input_format(path: Path, selected: str | None) -> ManifestFormat:
    if selected is not None:
        return ManifestFormat(selected)
    name = path.name.lower()
    if name.startswith("requirements") and name.endswith(".txt"):
        return ManifestFormat.REQUIREMENTS
    if name.startswith("package-lock") and name.endswith(".json"):
        return ManifestFormat.NPM_LOCK
    raise ScanError("unsupported_format", "Select the manifest format with --format.")


def _limits() -> ParseLimits:
    try:
        value = int(os.environ.get("DEPSCOPE_MAX_FILE_BYTES", "1000000"))
        if not 1 <= value < sys.maxsize:
            raise ValueError
        return ParseLimits(max_file_bytes=value)
    except ValueError as exc:
        raise ScanError(
            "invalid_file_limit", "DEPSCOPE_MAX_FILE_BYTES must be a positive byte count."
        ) from exc


async def _run(path: Path, format: ManifestFormat, live: bool, limits: ParseLimits) -> ScanResult:
    try:
        with path.open("rb") as file:
            data = file.read(limits.max_file_bytes + 1)
    except OSError as exc:
        raise ScanError("unreadable_manifest", "The selected manifest could not be read.") from exc
    if not live:
        provider = FixtureProvider(Path("samples/osv.json"))
        return await Scanner(provider, limits=limits).scan(data, format)
    async with OSVClient() as gateway:
        return await Scanner(gateway, limits=limits).scan(data, format)


def _summary(result: ScanResult) -> None:
    coverage = result.coverage
    print(f"DepScope | {result.provenance} | {result.status}")
    print(f"Entries {coverage.occurrences} | Unresolved {coverage.unresolved_occurrences}")
    print(
        f"Exact versions {coverage.exact_coordinates} | Assessed {coverage.assessed_coordinates}"
        f" | Partial {coverage.partial_coordinates} | Failed {coverage.failed_coordinates}"
    )
    index = f"{result.risk.index}/100" if result.risk.index is not None else "unavailable"
    print(f"Findings {len(result.findings)} | DepScope risk index {index}")
    for finding in result.findings:
        package = finding.coordinate
        fixes = ", ".join(sorted({fix.version for fix in finding.fixes})) or "none verified"
        print(f"  {package.ecosystem} {package.name}@{package.version}  {finding.advisory_id}")
        print(
            f"    {finding.priority.severity} | {finding.evidence_level} | advisory fixes {fixes}"
        )
    diagnostics = sorted({code for row in result.assessments for code in row.diagnostics})
    if diagnostics:
        print("Advisory diagnostics | " + ", ".join(diagnostics))
    if result.limitations:
        print("Coverage notes: " + ", ".join(result.limitations))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Temporary DepScope scan engine interface")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--format", choices=list(ManifestFormat))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--offline", action="store_true", help="Use bundled fixtures only")
    mode.add_argument("--live", action="store_true", help="Send exact package coordinates to OSV")
    parser.add_argument("--json", type=Path, metavar="FILE", help="Write JSON to a new file")
    options = parser.parse_args(argv)
    try:
        format = _input_format(options.manifest, options.format)
        result = asyncio.run(_run(options.manifest, format, options.live, _limits()))
        if options.json:
            try:
                with options.json.open("x", encoding="utf-8", newline="\n") as output:
                    output.write(to_json(result))
            except OSError as exc:
                raise ScanError(
                    "export_failed", "The JSON output needs a new writable file."
                ) from exc
        _summary(result)
    except ScanError as exc:
        print(f"{exc.code}: {exc}", file=sys.stderr)
        return 2
    return 0 if result.status is LookupStatus.COMPLETE else 1


if __name__ == "__main__":
    raise SystemExit(main())
