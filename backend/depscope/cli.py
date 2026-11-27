import argparse
import asyncio
import json
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager, nullcontext
from enum import IntEnum
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError

from . import __version__
from .demo import FixtureProvider
from .errors import ScanError
from .models import Coverage, LookupStatus, ManifestFormat, Provenance, ScanResult, Severity
from .osv import OSVClient, OSVConfig
from .parsers import DEFAULT_PARSE_LIMITS, ParseLimits
from .scanner import Scanner
from .scoring import SEVERITY_RANK
from .serialization import to_json
from .service.errors import ServiceError
from .service.samples import identify_sample
from .settings import Settings
from .storage.analysis_views import ScanComparison
from .storage.comparison import compare_reports
from .storage.database import database_path, database_ready, sqlite_engine, worker_lock
from .storage.models import ScanSource, ScanStatus
from .storage.repository import Pagination, ScanInput, ScanRepository, TransitionConflict
from .storage.views import ScanSort


class Exit(IntEnum):
    OK = 0
    POLICY = 1
    INPUT = 2
    INCOMPLETE = 3
    OPERATION = 4


_SEVERITIES = (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


def input_format(path: Path, selected: str | None) -> ManifestFormat:
    if selected is not None:
        return ManifestFormat(selected)
    name = path.name.lower()
    if name.startswith("requirements") and name.endswith(".txt"):
        return ManifestFormat.REQUIREMENTS
    if name.startswith("package-lock") and name.endswith(".json"):
        return ManifestFormat.NPM_LOCK
    raise ScanError("unsupported_format", "Select the manifest format with --manifest-format.")


def manifest_bytes(path: Path, limit: int) -> bytes:
    try:
        if not path.is_file():
            raise OSError
        with path.open("rb") as file:
            return file.read(limit + 1)
    except OSError as exc:
        raise ScanError("unreadable_manifest", "The selected manifest could not be read.") from exc


async def run_scan(
    content: bytes, format: ManifestFormat, live: bool, limits: ParseLimits, config: OSVConfig
) -> ScanResult:
    if not live:
        return await Scanner(FixtureProvider.bundled(), limits=limits).scan(content, format)
    async with OSVClient(config=config) as gateway:
        return await Scanner(gateway, limits=limits).scan(content, format)


def summary(result: ScanResult) -> str:
    coverage = result.coverage
    index = f"{result.risk.index}/100" if result.risk.index is not None else "unavailable"
    lines = [
        f"DepScope | {result.provenance} | {result.status}",
        f"Entries {coverage.occurrences} | Unresolved {coverage.unresolved_occurrences}",
        (
            f"Exact versions {coverage.exact_coordinates} "
            f"| Assessed {coverage.assessed_coordinates}"
            f" | Partial {coverage.partial_coordinates} | Failed {coverage.failed_coordinates}"
        ),
        f"Findings {len(result.findings)} | DepScope risk index {index}",
    ]
    for finding in result.findings:
        package = finding.coordinate
        fixes = ", ".join(sorted({fix.version for fix in finding.fixes})) or "none verified"
        lines.extend(
            (
                f"  {package.ecosystem} {package.name}@{package.version}  {finding.advisory_id}",
                f"    {finding.priority.severity} | {finding.evidence_level}"
                f" | advisory fixes {fixes}",
            )
        )
    diagnostics = sorted({code for row in result.assessments for code in row.diagnostics})
    if diagnostics:
        lines.append("Advisory diagnostics | " + ", ".join(diagnostics))
    if result.limitations:
        lines.append("Coverage notes: " + ", ".join(result.limitations))
    return "\n".join(lines) + "\n"


def write_export(path: Path, document: str) -> None:
    try:
        with path.open("x", encoding="utf-8", newline="\n") as output:
            output.write(document)
    except OSError as exc:
        raise ScanError("export_failed", "Choose a new writable output file.") from exc


def _bounded_integer(low: int, high: int) -> Callable[[str], int]:
    def number(value: str) -> int:
        result = int(value)
        if low <= result <= high:
            return result
        raise argparse.ArgumentTypeError(f"Use a value from {low} to {high}.")

    return number


def _output_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=("text", "json"), default="text", help="stdout format")
    parser.add_argument("--output", type=Path, help="also write JSON to a new file")


@contextmanager
def _storage(selected: Path | None, *, write: bool = False) -> Iterator[ScanRepository]:
    path = database_path(selected if selected is not None else Settings.load().database_path)
    if not path.is_file():
        raise ScanError("database_missing", "Initialize the database with alembic upgrade head.")
    with worker_lock(path) if write else nullcontext():
        engine = sqlite_engine(path, read_only=not write)
        try:
            if not database_ready(engine):
                raise ScanError(
                    "database_schema", "Upgrade the database with alembic upgrade head."
                )
            yield ScanRepository(engine)
        finally:
            engine.dispose()


def _insufficient(coverage: Coverage) -> bool:
    return bool(
        not coverage.assessed_coordinates
        or coverage.assessed_coordinates != coverage.exact_coordinates
        or coverage.unresolved_occurrences
    )


def _rank(severity: Severity | None) -> int:
    return SEVERITY_RANK[severity] if severity is not None else -1


def _compare_policy(comparison: ScanComparison, threshold: Severity) -> Exit:
    for scan in (comparison.baseline, comparison.target):
        if (
            scan.status != ScanStatus.COMPLETE
            or scan.coverage is None
            or _insufficient(scan.coverage)
            or (scan.severity_counts or {}).get(Severity.UNKNOWN, 0)
        ):
            return Exit.INCOMPLETE
    return (
        Exit.POLICY
        if any(
            _rank(change.after_severity) >= _rank(threshold) > _rank(change.before_severity)
            for change in comparison.findings
        )
        else Exit.OK
    )


def _emit(options: argparse.Namespace, text: str, document: str) -> None:
    if options.output:
        write_export(options.output, document)
    sys.stdout.write(document if options.format == "json" else text)


def _document(model: BaseModel, exit_code: Exit) -> str:
    return (
        json.dumps(
            {**model.model_dump(mode="json"), "exit_code": exit_code}, indent=2, ensure_ascii=True
        )
        + "\n"
    )


def _result_line(code: Exit, threshold: Severity | None) -> str:
    if code == Exit.INCOMPLETE:
        return "Incomplete evidence. Review lookup coverage, unresolved entries and severity.\n"
    if threshold is None:
        return ""
    state = "violated" if code == Exit.POLICY else "passed"
    return f"Policy {state} | severity threshold {threshold}\n"


def _scan(options: argparse.Namespace) -> Exit:
    defaults = DEFAULT_PARSE_LIMITS
    max_file_bytes = options.max_bytes or Settings.load().max_file_bytes
    limits = ParseLimits(
        max_file_bytes=max_file_bytes,
        max_occurrences=options.max_occurrences,
        max_coordinates=options.max_coordinates,
        max_lock_depth=defaults.max_lock_depth,
    )
    format = input_format(options.manifest, options.manifest_format)
    content = manifest_bytes(options.manifest, limits.max_file_bytes)
    config = OSVConfig(scan_timeout=options.timeout, request_timeout=options.request_timeout)
    result = asyncio.run(run_scan(content, format, options.live, limits, config))
    threshold = Severity(options.fail_on) if options.fail_on else None
    code = Exit.OK
    if (
        result.status != LookupStatus.COMPLETE
        or _insufficient(result.coverage)
        or (threshold is not None and result.risk.severity_counts.get(Severity.UNKNOWN, 0))
    ):
        code = Exit.INCOMPLETE
    elif threshold and any(
        _rank(item.priority.severity) >= _rank(threshold) for item in result.findings
    ):
        code = Exit.POLICY
    scan_id = None
    if options.save:
        sample_id = None
        if not options.live:
            sample_id = asyncio.run(identify_sample(format, content))
            if sample_id is None:
                raise ScanError(
                    "sample_required", "Saving an offline scan requires a bundled sample manifest."
                )
        with _storage(options.database, write=True) as repository:
            repository.reconcile()
            scan_id = repository.create(
                ScanInput(
                    format,
                    ScanSource.SAMPLE if sample_id else ScanSource.UPLOAD,
                    result.provenance,
                    sample_id,
                )
            ).id
            try:
                repository.start(scan_id)
                repository.finish(scan_id, result)
            except (SQLAlchemyError, TransitionConflict):
                repository.fail(scan_id, "storage_failed")
                raise
    message = summary(result) + (f"Saved scan {scan_id}\n" if scan_id else "")
    _emit(
        options,
        message + _result_line(code, threshold),
        to_json(result, metadata={"scan_id": scan_id, "exit_code": code}),
    )
    return code


def _history(options: argparse.Namespace, repository: ScanRepository) -> Exit:
    page = repository.list_scans(
        Pagination(options.page, options.page_size),
        provenance=options.provenance,
        status=options.status,
        format=None,
        sort=ScanSort.NEWEST,
    )
    lines = [f"Scan history | {page.total} records | page {page.page}"]
    for scan in page.items:
        risk = scan.risk_index if scan.risk_index is not None else "unavailable"
        lines.append(
            f"{scan.id}  {scan.requested_at.isoformat()}  {scan.format}  {scan.provenance}"
            f"  {scan.status}  risk {risk}"
        )
    _emit(options, "\n".join(lines) + "\n", _document(page, Exit.OK))
    return Exit.OK


def _saved(options: argparse.Namespace) -> Exit:
    with _storage(options.database) as repository:
        if options.command == "history":
            return _history(options, repository)
        scanning = options.command == "compare"
        report = repository.report(str(options.scan_id), include_evidence=not scanning)
        if report is None:
            raise ScanError("scan_not_found", "The selected scan was not found.")
        if report.scan.status in (ScanStatus.QUEUED, ScanStatus.RUNNING):
            raise ScanError("scan_pending", "Wait for the selected scan to finish.")
        if not scanning:
            lines = [
                f"Saved scan {report.scan.id} | {report.scan.provenance} | {report.scan.status}"
            ]
            if report.scan.error_code:
                lines.append(f"Diagnostic {report.scan.error_code}")
            for package in report.packages:
                key = package.coordinate
                lines.append(
                    f"{key.ecosystem} {key.name}@{key.version} | {package.finding_count} findings"
                    f" | {package.highest_severity} | {package.fixable_count} with fixes"
                )
            _emit(options, "\n".join(lines) + "\n", _document(report, Exit.OK))
            return Exit.OK
        target = repository.report(str(options.other_id), include_evidence=False)
    if target is None:
        raise ScanError("scan_not_found", "The comparison target was not found.")
    if report.scan.id == target.scan.id or report.scan.provenance != target.scan.provenance:
        raise ScanError("invalid_pair", "Choose two distinct scans from the same advisory source.")
    threshold = Severity(options.fail_on) if options.fail_on else None
    if target.scan.status in (ScanStatus.QUEUED, ScanStatus.RUNNING):
        raise ScanError("scan_pending", "Wait for the target scan to finish.")
    if report.scan.coverage is None or target.scan.coverage is None:
        raise ScanError("scan_result_unavailable", "Choose two scans with saved results.")
    if threshold and report.scan.format != target.scan.format:
        raise ScanError("invalid_pair", "Use the same manifest format for a comparison policy.")
    comparison = compare_reports(report, target)
    code = _compare_policy(comparison, threshold) if threshold is not None else Exit.OK
    lines = [
        f"Comparison | {comparison.baseline.provenance}",
        f"Baseline {comparison.baseline.id} | {comparison.baseline.status}",
        f"Target   {comparison.target.id} | {comparison.target.status}",
    ]
    for item in comparison.findings:
        lines.append(
            f"{item.kind.replace('_', ' ')} | {item.package.ecosystem} {item.package.name}"
            f" | {', '.join(item.advisory_ids)} | {item.before_severity or 'unavailable'} ->"
            f" {item.after_severity or 'unavailable'} | {item.context.replace('_', ' ')}"
        )
    lines.extend(
        f"Dependency {item.kind} | {item.package.ecosystem} {item.package.name}"
        f" | {', '.join(item.before_versions) or 'empty'} ->"
        f" {', '.join(item.after_versions) or 'empty'}"
        for item in comparison.dependencies
    )
    _emit(
        options,
        "\n".join(lines) + "\n" + _result_line(code, threshold),
        _document(comparison, code),
    )
    return code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="depscope", description="Dependency advisory analysis")
    parser.add_argument("--version", action="version", version=f"DepScope {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="scan an exact-version manifest")
    scan.add_argument("manifest", type=Path)
    scan.add_argument("--manifest-format", choices=list(ManifestFormat))
    mode = scan.add_mutually_exclusive_group(required=True)
    mode.add_argument("--offline", action="store_true", help="use the bundled fixture subset")
    mode.add_argument("--live", action="store_true", help="send exact coordinates to OSV")
    scan.add_argument("--max-bytes", type=_bounded_integer(1, 10_000_000))
    scan.add_argument("--max-occurrences", type=_bounded_integer(1, 5_000), default=5_000)
    scan.add_argument("--max-coordinates", type=_bounded_integer(1, 2_000), default=2_000)
    scan.add_argument(
        "--timeout", type=_bounded_integer(1, 300), default=45, help="OSV lookup deadline"
    )
    scan.add_argument("--request-timeout", type=_bounded_integer(1, 60), default=8)
    scan.add_argument("--save", action="store_true", help="persist the scan in a migrated database")

    history = commands.add_parser("history", help="list saved scan metadata")
    history.add_argument("--provenance", type=Provenance, choices=list(Provenance))
    history.add_argument("--status", type=ScanStatus, choices=list(ScanStatus))
    history.add_argument("--page", type=_bounded_integer(1, 1_000_000), default=1)
    history.add_argument("--page-size", type=_bounded_integer(1, 50), default=20)
    report = commands.add_parser("report", help="read a saved scan and its evidence")
    report.add_argument("scan_id", type=UUID)
    compare = commands.add_parser(
        "compare", help="compare saved scans and optionally apply a policy"
    )
    compare.add_argument("scan_id", type=UUID, metavar="BASELINE_ID")
    compare.add_argument("other_id", type=UUID, metavar="TARGET_ID")
    for command in (scan, compare):
        command.add_argument("--fail-on", choices=_SEVERITIES)
    for command in (scan, history, report, compare):
        command.add_argument("--database", type=Path, help="workspace SQLite file")
        _output_options(command)

    options = parser.parse_args(argv)
    try:
        return _scan(options) if options.command == "scan" else _saved(options)
    except ScanError as exc:
        print(f"{exc.code}: {exc}", file=sys.stderr)
        if exc.code in {"scan_pending", "scan_result_unavailable"}:
            return Exit.INCOMPLETE
        return (
            Exit.OPERATION
            if exc.code
            in {"database_missing", "database_schema", "invalid_fixture", "export_failed"}
            else Exit.INPUT
        )
    except ServiceError:
        print("sample_unavailable: A bundled sample could not be read.", file=sys.stderr)
    except ValueError:
        print(
            "invalid_configuration: Check the workspace database path and scan limits.",
            file=sys.stderr,
        )
    except (RuntimeError, SQLAlchemyError, TransitionConflict):
        print(
            "operation_failed: Check database availability and whether another worker owns it.",
            file=sys.stderr,
        )
    except KeyboardInterrupt:
        print("interrupted: The command was stopped.", file=sys.stderr)
    return Exit.OPERATION
