from collections import defaultdict
from collections.abc import Iterator
from dataclasses import replace
from urllib.parse import unquote, urlsplit

from .._json import InvalidPayload, decode_json, object_value
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

_ROOT_DEPENDENCY_KEYS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)
type _Entry = tuple[object, str | None, str | None, Directness, set[str]]


def _installed_path(path: str, depth_limit: int) -> tuple[str, int] | None:
    prefix = "node_modules/"
    if not path.startswith(prefix):
        return None
    segments = path[len(prefix) :].split("/node_modules/")
    if len(segments) > depth_limit:
        raise ScanError("lockfile_too_deep", "The lockfile exceeds the dependency depth limit.")
    if any(package_name(Ecosystem.NPM, part) is None for part in segments):
        return None
    return segments[-1], len(segments)


def _root_dependencies(root: object) -> dict[str, set[str]] | None:
    if root is None:
        return None
    metadata = object_value(root)
    declarations: dict[str, set[str]] = defaultdict(set)
    for key in _ROOT_DEPENDENCY_KEYS:
        for name, spec in object_value(metadata.get(key, {})).items():
            if package_name(Ecosystem.NPM, name) is not None:
                if not isinstance(spec, str):
                    raise InvalidPayload("invalid_root_dependency")
                declarations[name].add(spec)
    return declarations


def _alias_target(spec: str) -> str | None:
    value = spec.removeprefix("npm:")
    name = package_name(Ecosystem.NPM, value)
    if name is not None:
        return name
    package, separator, constraint = value.rpartition("@")
    return package_name(Ecosystem.NPM, package) if separator and constraint else None


def _public_tarball(resolved: object, name: str, version: str) -> bool:
    if resolved is None:
        return True
    if not isinstance(resolved, str) or len(resolved) > 2_048 or not resolved.isascii():
        return False
    try:
        url = urlsplit(resolved)
        artifact = f"{name}/-/{name.rsplit('/', 1)[-1]}-{version}.tgz"
        return (
            url.scheme == "https"
            and url.netloc == "registry.npmjs.org"
            and unquote(url.path) == f"/{artifact}"
            and not (url.query or url.fragment)
        )
    except ValueError:
        return False


def _occurrence(
    record: object,
    path: str | None,
    slot: str | None,
    directness: Directness,
    declarations: set[str],
    number: int,
) -> Occurrence:
    base = Occurrence(
        Ecosystem.NPM,
        Resolution.UNRESOLVED,
        directness,
        name=slot,
        dependency_path=path,
        entry_number=number,
    )
    if slot is None:
        return replace(base, reason="unsupported_install_path")
    if not isinstance(record, dict):
        return replace(base, resolution=Resolution.INVALID, reason="invalid_lock_entry")
    entry = object_value(record)
    if entry.get("link") is True or entry.get("inBundle") is True or entry.get("bundled") is True:
        return replace(base, reason="linked_or_bundled_source")
    declared_name = entry.get("name", slot)
    if not isinstance(declared_name, str):
        return replace(base, resolution=Resolution.INVALID, reason="invalid_package_name")
    name = package_name(Ecosystem.NPM, declared_name)
    version = entry.get("version")
    if name is None or not isinstance(version, str):
        return replace(base, resolution=Resolution.INVALID, reason="missing_package_identity")
    if version.startswith("npm:"):
        alias, separator, version = version[4:].rpartition("@")
        target = package_name(Ecosystem.NPM, alias) if separator else None
        if target is None or (name not in (slot, target)):
            return replace(base, reason="ambiguous_alias")
        name = target
    if declarations:
        targets = {_alias_target(spec) for spec in declarations if spec.startswith("npm:")}
        if targets:
            target, *_ = targets
            if (
                len(targets) != 1
                or target is None
                or any(not spec.startswith("npm:") for spec in declarations)
                or name not in (slot, target)
                or ("name" in entry and declared_name != target)
            ):
                return replace(base, reason="ambiguous_alias")
            name = target
        elif any(any(mark in spec for mark in (":", "/", "\\")) for spec in declarations):
            return replace(base, reason="unverified_registry_source")
    normalized = exact_version(Ecosystem.NPM, version)
    if normalized is None:
        return replace(base, reason="no_exact_registry_version")
    if not _public_tarball(entry.get("resolved"), name, version):
        return replace(base, reason="unverified_registry_source")
    return replace(
        base,
        name=name,
        resolution=Resolution.LOCKED,
        coordinate=Coordinate(Ecosystem.NPM, name, normalized),
    )


def _legacy_entries(
    entries: dict[str, object], depth_limit: int, depth: int = 1, parent: str | None = ""
) -> Iterator[_Entry]:
    for raw_name, value in entries.items():
        if depth > depth_limit:
            raise ScanError("lockfile_too_deep", "The lockfile exceeds the dependency depth limit.")
        name = package_name(Ecosystem.NPM, raw_name)
        path = f"{parent}node_modules/{name}" if parent is not None and name is not None else None
        yield (
            value,
            path,
            name if path is not None else None,
            (Directness.UNKNOWN if depth == 1 else Directness.TRANSITIVE),
            set(),
        )
        if isinstance(value, dict):
            children = object_value(value).get("dependencies", {})
            if isinstance(children, dict):
                yield from _legacy_entries(
                    object_value(children), depth_limit, depth + 1, f"{path}/" if path else None
                )
            else:
                yield children, path, name, Directness.UNKNOWN, set()


def _modern_entries(entries: dict[str, object], depth_limit: int) -> Iterator[_Entry]:
    declared = _root_dependencies(entries.get(""))
    for path, value in entries.items():
        if not path:
            continue
        installed = _installed_path(path, depth_limit)
        if installed is None:
            yield value, None, None, Directness.UNKNOWN, set()
            continue
        slot, depth = installed
        if depth == 1 and declared is None:
            directness = Directness.UNKNOWN
        elif depth == 1 and declared is not None and slot in declared:
            directness = Directness.DIRECT
        else:
            directness = Directness.TRANSITIVE
        specs = declared.get(slot, set()) if depth == 1 and declared is not None else set()
        yield value, path, slot, directness, specs


def parse(text: str, max_occurrences: int, max_depth: int) -> Manifest:
    try:
        root = object_value(decode_json(text))
        version = root.get("lockfileVersion")
        if type(version) is not int or version not in (1, 2, 3):
            raise ScanError(
                "unsupported_lockfile_version", "Supported npm lockfile versions are 1 through 3."
            )
        if version == 1:
            entries = _legacy_entries(object_value(root.get("dependencies", {})), max_depth)
        else:
            entries = _modern_entries(object_value(root.get("packages")), max_depth)
        occurrences: list[Occurrence] = []
        for number, (record, path, slot, directness, declarations) in enumerate(entries, 1):
            if number > max_occurrences:
                raise ScanError("too_many_entries", "The lockfile contains too many entries.")
            occurrences.append(_occurrence(record, path, slot, directness, declarations, number))
    except InvalidPayload as exc:
        raise ScanError(
            "invalid_lockfile", "The package lockfile is missing or malformed."
        ) from exc
    return Manifest(ManifestFormat.NPM_LOCK, tuple(occurrences), lockfile_version=version)
