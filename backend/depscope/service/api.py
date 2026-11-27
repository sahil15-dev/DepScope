import logging
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from typing import Annotated, Literal, cast
from uuid import UUID

from fastapi import FastAPI, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from .. import __version__
from ..demo import FixtureProvider
from ..identity import exact_version, package_name
from ..models import Coordinate, Occurrence, Provenance
from ..osv import OSVClient
from ..parsers import ParseLimits
from ..scanner import AdvisoryProvider, Scanner
from ..settings import Settings
from ..storage.analysis_views import CandidateUpgrade, PackagePage, ScanComparison, ScanReport
from ..storage.comparison import compare_reports
from ..storage.database import database_path, database_ready, sqlite_engine, worker_lock
from ..storage.models import ScanSource, ScanStatus
from ..storage.repository import ScanInput, ScanRepository
from ..storage.views import FindingsPage, Overview, Page, ScanDetail, ScanSummary
from .errors import ErrorResponse, ServiceError, database_unavailable, scan_not_found
from .jobs import ScanJobs
from .requests import (
    CoordinateQuery,
    FindingsQuery,
    HistoryQuery,
    OverviewQuery,
    PackageQuery,
    PageQuery,
    Submission,
    check_media,
    read_body,
)
from .samples import read_sample
from .security import LocalRequests

_LOG = logging.getLogger(__name__)


class Accepted(BaseModel):
    id: str
    status: Literal[ScanStatus.QUEUED] = ScanStatus.QUEUED
    status_url: str


class Health(BaseModel):
    status: Literal["ready"] = "ready"
    database: Literal["ready"] = "ready"


@dataclass(frozen=True, slots=True)
class Services:
    engine: Engine
    repository: ScanRepository
    jobs: ScanJobs


def _services(request: Request) -> Services:
    return cast(Services, request.app.state.services)


def create_app(
    settings: Settings | None = None, *, live_provider: AdvisoryProvider | None = None
) -> FastAPI:
    options = settings or Settings.load()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        path = database_path(options.database_path)
        if not path.is_file():
            raise RuntimeError("Initialize the DepScope database with `alembic upgrade head`")
        with worker_lock(path):
            engine = sqlite_engine(path)
            try:
                if not await run_in_threadpool(database_ready, engine):
                    raise RuntimeError("Upgrade the DepScope database with `alembic upgrade head`")
                repository = ScanRepository(engine)
                await run_in_threadpool(repository.reconcile)
                limits = ParseLimits(max_file_bytes=options.max_file_bytes)
                demo = FixtureProvider.bundled()
                async with AsyncExitStack() as stack:
                    provider: AdvisoryProvider = (
                        live_provider
                        if live_provider is not None
                        else await stack.enter_async_context(OSVClient())
                    )
                    jobs = ScanJobs(
                        repository,
                        {
                            Provenance.LIVE_OSV: Scanner(provider, limits=limits),
                            Provenance.OFFLINE_FIXTURE: Scanner(demo, limits=limits),
                        },
                        options,
                    )
                    app.state.services = Services(engine, repository, jobs)
                    try:
                        yield
                    finally:
                        await jobs.close()
                        try:
                            await run_in_threadpool(repository.reconcile)
                        except SQLAlchemyError:
                            _LOG.warning("Could not reconcile pending scans during shutdown")
            finally:
                await run_in_threadpool(engine.dispose)

    app = FastAPI(
        title="DepScope",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        description="Loopback API for dependency scans and historical advisory snapshots.",
        responses={422: {"model": ErrorResponse}, 503: {"model": ErrorResponse}},
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(options.allowed_origins),
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
        expose_headers=["Location", "Retry-After"],
    )
    app.add_middleware(LocalRequests, origins=options.allowed_origins)

    @app.exception_handler(ServiceError)
    async def handle_service(_request: Request, exc: ServiceError) -> JSONResponse:
        return exc.response()

    @app.exception_handler(RequestValidationError)
    async def handle_validation(_request: Request, _exc: RequestValidationError) -> JSONResponse:
        return ServiceError(
            422, "invalid_request", "One or more request parameters are invalid."
        ).response()

    @app.exception_handler(HTTPException)
    async def handle_http(_request: Request, exc: HTTPException) -> JSONResponse:
        response = ServiceError(
            exc.status_code, "http_error", "The request could not be routed."
        ).response()
        if exc.headers:
            response.headers.update(exc.headers)
        return response

    @app.exception_handler(SQLAlchemyError)
    async def handle_database(_request: Request, _exc: SQLAlchemyError) -> JSONResponse:
        return database_unavailable().response()

    @app.post(
        "/api/scans",
        status_code=202,
        response_model=Accepted,
        responses={code: {"model": ErrorResponse} for code in (400, 403, 408, 413, 415, 429)},
        openapi_extra={
            "requestBody": {
                "content": {
                    media: {"schema": {"type": "string", "format": "binary"}}
                    for media in ("text/plain", "application/json", "application/octet-stream")
                }
            }
        },
    )
    async def submit(
        request: Request, response: Response, query: Annotated[Submission, Query()]
    ) -> Accepted:
        jobs = _services(request).jobs
        if query.sample_id is not None:
            if query.format or query.source or query.live:
                raise ServiceError(
                    422, "invalid_submission", "Supply only sample_id for an offline scan."
                )
        elif (
            query.format is None
            or query.source not in (ScanSource.PASTE, ScanSource.UPLOAD)
            or not query.live
        ):
            raise ServiceError(
                422, "invalid_submission", "A manifest scan needs format, source, and live=true."
            )
        else:
            check_media(request, query.format)

        jobs.reserve()
        enqueued = False
        try:
            if query.sample_id is not None:
                await read_body(request, 0, options.upload_timeout)
                sample, content = await read_sample(query.sample_id, options.max_file_bytes)
                metadata = ScanInput(
                    sample.format, ScanSource.SAMPLE, Provenance.OFFLINE_FIXTURE, query.sample_id
                )
            else:
                assert query.format is not None and query.source is not None
                content = await read_body(request, options.max_file_bytes, options.upload_timeout)
                metadata = ScanInput(query.format, query.source, Provenance.LIVE_OSV)
            scan = await jobs.enqueue(metadata, content)
            enqueued = True
        finally:
            if not enqueued:
                jobs.release()
        status_url = f"/api/scans/{scan.id}"
        response.headers["Location"] = status_url
        return Accepted(id=scan.id, status_url=status_url)

    @app.get("/api/scans")
    def history(request: Request, query: Annotated[HistoryQuery, Query()]) -> Page[ScanSummary]:
        return _services(request).repository.list_scans(
            query.pagination,
            provenance=query.provenance,
            status=query.status,
            format=query.format,
            sort=query.sort,
        )

    @app.get("/api/scans/{scan_id}", responses={404: {"model": ErrorResponse}})
    def status(request: Request, scan_id: UUID, query: Annotated[PageQuery, Query()]) -> ScanDetail:
        result = _services(request).repository.detail(str(scan_id), query.pagination)
        if result is None:
            raise scan_not_found()
        return result

    @app.get("/api/scans/{scan_id}/findings", responses={404: {"model": ErrorResponse}})
    def findings(
        request: Request, scan_id: UUID, query: Annotated[FindingsQuery, Query()]
    ) -> FindingsPage:
        result = _services(request).repository.findings(
            str(scan_id),
            query.pagination,
            ecosystem=query.ecosystem,
            severity=query.severity,
            package=query.package,
            fix_available=query.fix_available,
            sort=query.sort,
            name=query.name,
            version=query.version,
        )
        if result is None:
            raise scan_not_found()
        return result

    @app.get("/api/scans/{scan_id}/packages")
    def packages(
        request: Request, scan_id: UUID, query: Annotated[PackageQuery, Query()]
    ) -> PackagePage:
        result = _services(request).repository.groups(
            str(scan_id),
            query.pagination,
            ecosystem=query.ecosystem,
            severity=query.severity,
            package=query.package,
            fix_available=query.fix_available,
            sort=query.sort,
        )
        if result is None:
            raise scan_not_found()
        return result

    @app.get("/api/scans/{scan_id}/review")
    def review(
        request: Request, scan_id: UUID, query: Annotated[PageQuery, Query()]
    ) -> Page[Occurrence]:
        result = _services(request).repository.review(str(scan_id), query.pagination)
        if result is None:
            raise scan_not_found()
        return result

    @app.get("/api/scans/{scan_id}/candidates")
    def candidates(
        request: Request, scan_id: UUID, query: Annotated[CoordinateQuery, Query()]
    ) -> list[CandidateUpgrade]:
        name = package_name(query.ecosystem, query.name)
        version = exact_version(query.ecosystem, query.version)
        if not name or not version:
            raise ServiceError(422, "invalid_coordinate", "Choose an exact package version.")
        result = _services(request).repository.candidates(
            str(scan_id), Coordinate(query.ecosystem, name, version)
        )
        if result is None:
            raise scan_not_found()
        return result

    @app.get("/api/scans/{scan_id}/comparison/{other_id}")
    def comparison(request: Request, scan_id: UUID, other_id: UUID) -> ScanComparison:
        if scan_id == other_id:
            raise ServiceError(422, "same_scan", "Choose two different saved scans.")
        repository = _services(request).repository
        baseline = repository.report(str(scan_id), include_evidence=False)
        target = repository.report(str(other_id), include_evidence=False)
        if baseline is None or target is None:
            raise scan_not_found()
        if baseline.scan.provenance != target.scan.provenance:
            raise ServiceError(
                409, "different_sources", "Compare two fixture scans or two live scans."
            )
        if any(
            item.scan.status in (ScanStatus.QUEUED, ScanStatus.RUNNING)
            for item in (baseline, target)
        ):
            raise ServiceError(
                409, "scan_pending", "Wait until both scans finish before comparing."
            )
        if baseline.scan.coverage is None or target.scan.coverage is None:
            raise ServiceError(
                409, "scan_result_unavailable", "Choose two scans with saved dependency results."
            )
        return compare_reports(baseline, target)

    @app.get("/api/scans/{scan_id}/report")
    def report(
        request: Request, response: Response, scan_id: UUID, download: bool = False
    ) -> ScanReport:
        result = _services(request).repository.report(str(scan_id))
        if result is None:
            raise scan_not_found()
        if result.scan.status in (ScanStatus.QUEUED, ScanStatus.RUNNING):
            raise ServiceError(
                409, "scan_pending", "Wait until the scan finishes before exporting."
            )
        response.headers["Cache-Control"] = "no-store"
        if download:
            response.headers["Content-Disposition"] = (
                f'attachment; filename="depscope-{scan_id}.json"'
            )
        return result

    @app.get("/api/overview")
    def overview(request: Request, query: Annotated[OverviewQuery, Query()]) -> Overview:
        return _services(request).repository.overview(query.provenance, query.limit)

    @app.get("/api/health")
    def health(request: Request) -> Health:
        if not database_ready(_services(request).engine):
            raise database_unavailable()
        return Health()

    return app
