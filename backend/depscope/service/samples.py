from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from starlette.concurrency import run_in_threadpool

from ..models import ManifestFormat
from ..parsers import DEFAULT_PARSE_LIMITS
from .errors import ServiceError


class SampleId(StrEnum):
    PYTHON_VULNERABLE = "python-vulnerable"
    NPM_VULNERABLE = "npm-vulnerable"
    PYTHON_CLEAN = "python-clean"
    PYTHON_MIXED = "python-mixed"
    PYTHON_PARTIAL = "python-partial"


@dataclass(frozen=True, slots=True)
class Sample:
    format: ManifestFormat
    name: str


SAMPLES = {
    SampleId.PYTHON_VULNERABLE: Sample(ManifestFormat.REQUIREMENTS, "requirements-vulnerable.txt"),
    SampleId.NPM_VULNERABLE: Sample(ManifestFormat.NPM_LOCK, "package-lock-vulnerable.json"),
    SampleId.PYTHON_CLEAN: Sample(ManifestFormat.REQUIREMENTS, "requirements-clean.txt"),
    SampleId.PYTHON_MIXED: Sample(ManifestFormat.REQUIREMENTS, "requirements-mixed.txt"),
    SampleId.PYTHON_PARTIAL: Sample(ManifestFormat.REQUIREMENTS, "requirements-partial.txt"),
}


async def read_sample(sample_id: SampleId, limit: int) -> tuple[Sample, bytes]:
    sample = SAMPLES[sample_id]

    def read() -> bytes:
        path = Path("samples") / sample.name
        if not path.resolve().is_relative_to(Path.cwd().resolve()):
            raise OSError("Sample is outside the application workspace")
        with path.open("rb") as source:
            return source.read(limit + 1)

    try:
        content = await run_in_threadpool(read)
    except OSError:
        raise ServiceError(
            503, "sample_unavailable", "The bundled sample is unavailable."
        ) from None
    if len(content) > limit:
        raise ServiceError(413, "input_too_large", "The sample exceeds the configured byte limit.")
    return sample, content


async def identify_sample(format: ManifestFormat, content: bytes) -> SampleId | None:
    for identifier, sample in SAMPLES.items():
        if sample.format != format:
            continue
        _, bundled = await read_sample(identifier, DEFAULT_PARSE_LIMITS.max_file_bytes)
        if bundled == content:
            return identifier
    return None
