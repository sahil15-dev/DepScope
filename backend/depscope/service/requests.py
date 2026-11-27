import asyncio
from typing import Annotated

from fastapi import Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.requests import ClientDisconnect

from ..models import Ecosystem, ManifestFormat, Provenance, Severity
from ..storage.models import ScanSource, ScanStatus
from ..storage.repository import Pagination
from ..storage.views import FindingSort, ScanSort
from .errors import ServiceError
from .samples import SampleId


class Submission(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format: ManifestFormat | None = None
    source: ScanSource | None = None
    live: bool = False
    sample_id: SampleId | None = None


class PageQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    page: Annotated[int, Field(ge=1, le=100_000)] = 1
    page_size: Annotated[int, Field(ge=1, le=50)] = 20

    @property
    def pagination(self) -> Pagination:
        return Pagination(self.page, self.page_size)


class HistoryQuery(PageQuery):
    provenance: Provenance | None = None
    status: ScanStatus | None = None
    format: ManifestFormat | None = None
    sort: ScanSort = ScanSort.NEWEST


class FindingsQuery(PageQuery):
    ecosystem: Ecosystem | None = None
    severity: Severity | None = None
    package: Annotated[str | None, Field(min_length=1, max_length=214)] = None
    fix_available: bool | None = None
    sort: FindingSort = FindingSort.PRIORITY


class OverviewQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provenance: Provenance | None = Provenance.LIVE_OSV
    limit: Annotated[int, Field(ge=1, le=50)] = 10


def check_media(request: Request, format: ManifestFormat) -> None:
    expected = "text/plain" if format is ManifestFormat.REQUIREMENTS else "application/json"
    media = request.headers.get("Content-Type", "").partition(";")[0].strip().lower()
    if media not in (expected, "application/octet-stream"):
        raise ServiceError(415, "unsupported_media_type", "Send raw UTF-8 manifest bytes.")


async def read_body(request: Request, maximum: int, timeout: int) -> bytes:
    encodings = request.headers.getlist("Content-Encoding")
    if encodings and [encoding.lower() for encoding in encodings] != ["identity"]:
        raise ServiceError(415, "unsupported_content_encoding", "Send an uncompressed request.")
    lengths = request.headers.getlist("Content-Length")
    declared = None
    if lengths:
        value = lengths[0]
        if len(lengths) != 1 or not value.isascii() or not value.isdecimal():
            raise ServiceError(
                400, "invalid_content_length", "The Content-Length header is invalid."
            )
        if len(value) > 12 or int(value) > maximum:
            raise _oversize(maximum)
        declared = int(value)
    data = bytearray()
    try:
        async with asyncio.timeout(timeout):
            async for chunk in request.stream():
                if len(data) + len(chunk) > maximum:
                    raise _oversize(maximum)
                data.extend(chunk)
    except TimeoutError:
        raise ServiceError(408, "upload_timeout", "The upload did not finish in time.") from None
    except ClientDisconnect:
        raise ServiceError(400, "upload_disconnected", "The upload was interrupted.") from None
    if declared is not None and len(data) != declared:
        raise ServiceError(
            400, "invalid_content_length", "The request size did not match Content-Length."
        )
    return bytes(data)


def _oversize(maximum: int) -> ServiceError:
    if not maximum:
        return ServiceError(
            400, "unexpected_body", "Bundled sample scans use an empty request body."
        )
    return ServiceError(413, "input_too_large", "The manifest exceeds the configured byte limit.")
