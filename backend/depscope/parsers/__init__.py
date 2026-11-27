from dataclasses import dataclass

from ..errors import ScanError
from ..models import Manifest, ManifestFormat
from . import npm, requirements


@dataclass(frozen=True, slots=True)
class ParseLimits:
    max_file_bytes: int = 1_000_000
    max_occurrences: int = 5_000
    max_coordinates: int = 2_000
    max_lock_depth: int = 40

    def __post_init__(self) -> None:
        if (
            min(
                self.max_file_bytes, self.max_occurrences, self.max_coordinates, self.max_lock_depth
            )
            < 1
            or self.max_lock_depth > 80
        ):
            raise ValueError("Parser limits must be positive and lock depth at most 80")


DEFAULT_PARSE_LIMITS = ParseLimits()


def parse_manifest(
    content: bytes, format: ManifestFormat, *, limits: ParseLimits = DEFAULT_PARSE_LIMITS
) -> Manifest:
    if len(content) > limits.max_file_bytes:
        raise ScanError("input_too_large", "The manifest exceeds the configured byte limit.")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ScanError("invalid_encoding", "The manifest must be UTF-8 text.") from exc
    if "\x00" in text:
        raise ScanError("invalid_encoding", "The manifest contains a NUL character.")

    match format:
        case ManifestFormat.REQUIREMENTS:
            manifest = requirements.parse(text, limits.max_occurrences)
        case ManifestFormat.NPM_LOCK:
            manifest = npm.parse(text, limits.max_occurrences, limits.max_lock_depth)
        case _:
            raise ScanError("unsupported_format", "Select a supported manifest format.")
    if len(manifest.coordinates) > limits.max_coordinates:
        raise ScanError("too_many_coordinates", "The manifest contains too many distinct versions.")
    return manifest
