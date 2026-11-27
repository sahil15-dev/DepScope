import re
from datetime import UTC, datetime
from urllib.parse import urlsplit

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError

from ._json import InvalidPayload, array_value, object_value
from .models import (
    Advisory,
    AffectedPackage,
    AffectedRange,
    RangeEvent,
    Reference,
    Severity,
    SeverityEvidence,
)

_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}", re.ASCII)
_RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", re.ASCII
)
_CVSS4_BASE = frozenset(("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"))
_LABELS = {severity.value: severity for severity in Severity}
_LABELS["moderate"] = Severity.MEDIUM


def advisory_id(value: object) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise InvalidPayload("invalid_advisory_id")
    return value


def timestamp(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 40 or not _RFC3339.fullmatch(value):
        raise InvalidPayload("invalid_timestamp")
    try:
        return datetime.fromisoformat(value).astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise InvalidPayload("invalid_timestamp") from exc


def _optional_timestamp(record: dict[str, object], key: str) -> datetime | None:
    return timestamp(record[key]) if key in record else None


def _text(value: object, max_length: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise InvalidPayload("invalid_string")
    return value


def _safe_link(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 4096 or "\\" in value:
        return None
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    try:
        url = urlsplit(value)
        if url.scheme in ("http", "https") and url.hostname and url.username is None:
            return value
    except ValueError:
        pass
    return None


def _cvss_score(scheme: str, vector: str) -> float | None:
    try:
        if scheme == "CVSS_V2":
            return float(CVSS2(vector).scores()[0])
        if scheme == "CVSS_V3" and vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
            return float(CVSS3(vector).scores()[0])
        if scheme == "CVSS_V4" and vector.startswith("CVSS:4.0/"):
            CVSS4(vector)  # Validate the full vector before deriving its base-only score.
            metrics = [
                item for item in vector.split("/")[1:] if item.partition(":")[0] in _CVSS4_BASE
            ]
            return float(CVSS4("CVSS:4.0/" + "/".join(metrics)).scores()[0])
    except (CVSSError, ValueError):
        pass
    return None


def _severity_from_score(scheme: str, score: float | None) -> Severity:
    if score is None:
        return Severity.UNKNOWN
    if scheme != "CVSS_V2" and score == 0:
        return Severity.NONE
    if scheme != "CVSS_V2" and score >= 9:
        return Severity.CRITICAL
    if score >= 7:
        return Severity.HIGH
    if score >= 4:
        return Severity.MEDIUM
    return Severity.LOW


def _severity(record: dict[str, object], scope: str) -> tuple[SeverityEvidence, ...]:
    result: list[SeverityEvidence] = []
    for item in array_value(record.get("severity", [])):
        entry = object_value(item)
        scheme = _text(entry.get("type"), 48)
        vector = _text(entry.get("score"), 512)
        score = _cvss_score(scheme, vector)
        result.append(
            SeverityEvidence(
                scheme,
                f"{scope}.severity",
                _severity_from_score(scheme, score),
                vector=vector,
                score=score,
                score_basis="base_vector" if score is not None else None,
                upstream_source=_text(entry["source"], 512) if "source" in entry else None,
            )
        )
    for namespace in ("ecosystem_specific", "database_specific"):
        metadata = object_value(record.get(namespace, {}))
        label = metadata.get("severity")
        if isinstance(label, str) and len(label) <= 48:
            result.append(
                SeverityEvidence(
                    "categorical",
                    f"{scope}.{namespace}.severity",
                    _LABELS.get(label.strip().lower(), Severity.UNKNOWN),
                    label=label,
                )
            )
    return tuple(result)


def _range(value: object) -> AffectedRange:
    record = object_value(value)
    events: list[RangeEvent] = []
    for item in array_value(record.get("events")):
        event = object_value(item)
        if len(event) != 1:
            raise InvalidPayload("invalid_range_event")
        kind, version = next(iter(event.items()))
        events.append(RangeEvent(_text(kind, 48), _text(version, 256)))
    return AffectedRange(
        _text(record.get("type"), 48), tuple(events), _safe_link(record.get("repo"))
    )


def _affected(value: object) -> AffectedPackage:
    record = object_value(value)
    package = object_value(record.get("package", {}))
    return AffectedPackage(
        _text(package["ecosystem"], 128) if "ecosystem" in package else None,
        _text(package["name"], 512) if "name" in package else None,
        tuple(_text(version, 256) for version in array_value(record.get("versions", []))),
        tuple(_range(item) for item in array_value(record.get("ranges", []))),
        _severity(record, "affected"),
    )


def parse_advisory(value: object, expected_id: str) -> Advisory:
    record = object_value(value)
    identifier = advisory_id(record.get("id"))
    if identifier != expected_id:
        raise InvalidPayload("advisory_id_mismatch")
    refs: set[Reference] = {Reference("OSV", f"https://osv.dev/vulnerability/{identifier}")}
    for item in array_value(record.get("references", [])):
        reference = object_value(item)
        kind = _text(reference.get("type"), 48)
        url = _safe_link(reference.get("url"))
        if url and kind not in ("EVIDENCE", "DETECTION"):
            refs.add(Reference(kind, url))
    aliases = {advisory_id(item) for item in array_value(record.get("aliases", []))} - {identifier}
    return Advisory(
        identifier,
        timestamp(record.get("modified")),
        _optional_timestamp(record, "published"),
        _optional_timestamp(record, "withdrawn"),
        _text(record["summary"]) if record.get("summary") else None,
        tuple(sorted(aliases)),
        tuple(_affected(item) for item in array_value(record.get("affected", []))),
        _severity(record, "advisory"),
        tuple(sorted(refs, key=lambda ref: (ref.kind, ref.url))),
    )
