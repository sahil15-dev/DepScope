import re
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import replace

from packaging.requirements import InvalidRequirement, Requirement

from ..errors import ScanError
from ..identity import exact_version, package_name
from ..models import (
    Coordinate,
    Directness,
    Ecosystem,
    Manifest,
    ManifestFormat,
    Occurrence,
    Resolution,
)

_COMMENT = re.compile(r"(?<!\S)#.*$")
_HASH_START = re.compile(r"(?<!\S)--hash(?=[=\s]|$)")
_HASHES = re.compile(
    r"--hash(?:=|\s+)(?:sha256:[\da-fA-F]{64}|"
    r"sha384:[\da-fA-F]{96}|sha512:[\da-fA-F]{128})(?=\s|$)",
    re.ASCII,
)
_SOURCE_OVERRIDE = re.compile(
    r"^(?:--(?:index-url|extra-index-url|find-links|no-index)(?=\s|=|$)|-[if])"
)
_EDITABLE = re.compile(r"^(?:--editable(?=\s|=|$)|-e)")
_INCLUDE = re.compile(r"^(?:--(?:requirement|constraint)(?=\s|=|$)|-[rc])")


def _logical_lines(text: str) -> Iterator[tuple[int, str, bool]]:
    parts: list[str] = []
    start = 0
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not parts:
            start = number
        line = raw.rstrip()
        if line.endswith("\\"):
            parts.append(line[:-1])
            continue
        parts.append(line)
        yield start, _COMMENT.sub("", "".join(parts)).strip(), True
        parts.clear()
    if parts:
        yield start, "", False


def _parse_line(line: str, number: int, complete: bool) -> Occurrence:
    base = Occurrence(Ecosystem.PYPI, Resolution.UNRESOLVED, Directness.DECLARED, line=number)
    if not complete or len(line) > 4_096:
        return replace(base, resolution=Resolution.INVALID, reason="invalid_logical_line")
    if line.startswith("-"):
        reason = "unsupported_directive"
        if _SOURCE_OVERRIDE.match(line):
            reason = "package_index_override"
        elif _EDITABLE.match(line):
            reason = "editable_install"
        elif _INCLUDE.match(line):
            reason = "file_directive"
        return replace(base, reason=reason)
    if line.startswith((".", "/", "\\", "~")) or re.match(r"^[A-Za-z]:[\\/]", line):
        return replace(base, reason="local_reference")
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", line):
        return replace(base, reason="external_reference")
    # Bare local archive names can otherwise be syntactically valid package names.
    if line.endswith((".whl", ".zip", ".tar.gz", ".tgz", ".tar.bz2")):
        return replace(base, reason="local_reference")

    hash_start = _HASH_START.search(line)
    if hash_start is not None:
        if _HASHES.sub("", line[hash_start.start() :]).strip():
            return replace(base, resolution=Resolution.INVALID, reason="invalid_hash_option")
        line = line[: hash_start.start()].rstrip()
    try:
        req = Requirement(line)
    except InvalidRequirement:
        return replace(base, resolution=Resolution.INVALID, reason="invalid_requirement")
    name = package_name(Ecosystem.PYPI, req.name)
    if name is None:
        return replace(base, resolution=Resolution.INVALID, reason="invalid_package_name")
    extras = tuple(
        sorted({item for extra in req.extras if (item := package_name(Ecosystem.PYPI, extra))})
    )
    base = replace(base, name=name, extras=extras)
    if req.url:
        return replace(base, reason="external_reference")
    specifiers = list(req.specifier)
    if any(item.operator == "===" for item in specifiers):
        return replace(base, reason="arbitrary_version_equality")
    constraint = str(req.specifier)
    if len(constraint) > 256:
        return replace(base, reason="constraint_too_long")
    base = replace(base, constraint=constraint or None)
    if req.marker is not None:
        return replace(base, reason="target_environment_required")
    if not specifiers:
        return replace(base, resolution=Resolution.UNPINNED, reason="no_version_specifier")
    if (
        len(specifiers) == 1
        and specifiers[0].operator == "=="
        and not specifiers[0].version.endswith(".*")
    ):
        version = exact_version(Ecosystem.PYPI, specifiers[0].version)
        if version is not None:
            return replace(
                base,
                resolution=Resolution.DECLARED_PIN,
                coordinate=Coordinate(Ecosystem.PYPI, name, version),
            )
        return replace(base, reason="unsupported_version")
    return replace(base, resolution=Resolution.RANGE, reason="no_single_exact_pin")


def parse(text: str, max_occurrences: int) -> Manifest:
    occurrences: list[Occurrence] = []
    versions: dict[str, set[str]] = defaultdict(set)
    for number, line, complete in _logical_lines(text):
        if len(occurrences) >= max_occurrences:
            raise ScanError("too_many_entries", "The requirements file contains too many entries.")
        occurrence = _parse_line(line, number, complete)
        occurrences.append(occurrence)
        if occurrence.coordinate:
            versions[occurrence.coordinate.name].add(occurrence.coordinate.version)

    index_override = any(item.reason == "package_index_override" for item in occurrences)
    for index, occurrence in enumerate(occurrences):
        coordinate = occurrence.coordinate
        if coordinate and (index_override or len(versions[coordinate.name]) > 1):
            reason = "package_index_override" if index_override else "conflicting_pins"
            occurrences[index] = replace(
                occurrence, coordinate=None, resolution=Resolution.UNRESOLVED, reason=reason
            )
    return Manifest(ManifestFormat.REQUIREMENTS, tuple(occurrences))
