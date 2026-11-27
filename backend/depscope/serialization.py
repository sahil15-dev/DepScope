import json
from collections.abc import Mapping
from dataclasses import asdict
from datetime import datetime

from .models import ScanResult


def _encode(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    raise TypeError(f"Unsupported result type: {type(value).__name__}")


def to_json(result: ScanResult, *, metadata: Mapping[str, str | int | None] | None = None) -> str:
    advisories: dict[str, object] = {}
    assessments: list[dict[str, object]] = []
    for assessment in result.assessments:
        observations: list[dict[str, object]] = []
        for observation in assessment.observations:
            advisory = observation.advisory
            if advisory and advisory.id not in advisories:
                advisories[advisory.id] = asdict(advisory)
            observations.append(
                {
                    "discovery": asdict(observation.discovery),
                    "advisory_id": advisory.id if advisory else None,
                    "error": observation.error,
                }
            )
        assessments.append(
            {
                "coordinate": asdict(assessment.coordinate),
                "status": assessment.status,
                "observations": observations,
                "diagnostics": assessment.diagnostics,
            }
        )
    document = {
        "schema_version": result.schema_version,
        "observed_at": result.observed_at,
        "provenance": result.provenance,
        "status": result.status,
        "manifest": asdict(result.manifest),
        "coverage": asdict(result.coverage),
        "assessments": assessments,
        "advisories": advisories,
        "findings": [asdict(item) for item in result.findings],
        "risk": asdict(result.risk),
        "limitations": result.limitations,
        **(metadata or {}),
    }
    return (
        json.dumps(document, indent=2, allow_nan=False, ensure_ascii=True, default=_encode) + "\n"
    )
