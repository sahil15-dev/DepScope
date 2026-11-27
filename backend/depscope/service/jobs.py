import asyncio
import logging
import math
from collections import deque
from dataclasses import dataclass
from time import monotonic

from anyio import CancelScope
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool

from ..errors import ScanError
from ..models import Provenance, ScanResult
from ..scanner import Scanner
from ..settings import Settings
from ..storage.repository import ScanInput, ScanRepository, TransitionConflict
from ..storage.views import ScanSummary
from .errors import ServiceError

_LOG = logging.getLogger(__name__)
_RATE_WINDOW = 60
_PARSE_ERRORS = frozenset(
    {
        "input_too_large",
        "invalid_encoding",
        "unsupported_format",
        "too_many_coordinates",
        "too_many_entries",
        "invalid_lockfile",
        "lockfile_too_deep",
        "unsupported_lockfile_version",
    }
)


@dataclass(frozen=True, slots=True)
class Job:
    id: str
    input: ScanInput
    content: bytes


class ScanJobs:
    def __init__(
        self,
        repository: ScanRepository,
        scanners: dict[Provenance, Scanner],
        settings: Settings,
    ) -> None:
        self._repository = repository
        self._scanners = scanners
        self._settings = settings
        self._capacity = 1 + settings.max_pending_jobs
        self._reserved = 0
        self._admissions: deque[float] = deque()
        self._queue: asyncio.Queue[Job | None] = asyncio.Queue(maxsize=self._capacity)
        self._closing = False
        self._active_scan: asyncio.Task[ScanResult] | None = None
        self._worker = asyncio.create_task(self._work(), name="depscope-scan-worker")

    def reserve(self) -> None:
        now = monotonic()
        while self._admissions and now - self._admissions[0] >= _RATE_WINDOW:
            self._admissions.popleft()
        if len(self._admissions) >= self._settings.submissions_per_minute:
            retry = max(1, math.ceil(_RATE_WINDOW - (now - self._admissions[0])))
            raise ServiceError(
                429,
                "submission_rate_limited",
                "The local scan submission limit was reached.",
                Retry_After=str(retry),
            )
        if self._reserved >= self._capacity:
            raise ServiceError(
                503,
                "scan_queue_full",
                "All scan slots are currently in use.",
                Retry_After="1",
            )
        self._admissions.append(now)
        self._reserved += 1

    def release(self) -> None:
        self._reserved -= 1

    async def enqueue(self, metadata: ScanInput, content: bytes) -> ScanSummary:
        # Finish the small admission transaction and hand-off even if the HTTP client disconnects.
        with CancelScope(shield=True):
            scan = await run_in_threadpool(self._repository.create, metadata)
            self._queue.put_nowait(Job(scan.id, metadata, content))
        return scan

    async def close(self) -> None:
        self._closing = True
        if self._active_scan is not None:
            self._active_scan.cancel()
        while not self._queue.empty():
            self._queue.get_nowait()
            self._queue.task_done()
            self.release()
        self._queue.put_nowait(None)
        await self._worker

    async def _work(self) -> None:
        while True:
            job = await self._queue.get()
            if job is None:
                self._queue.task_done()
                return
            try:
                await self._execute(job)
            finally:
                self.release()
                self._queue.task_done()
                del job

    async def _execute(self, job: Job) -> None:
        try:
            await run_in_threadpool(self._repository.start, job.id)
            if self._closing:
                return
            async with asyncio.timeout(self._settings.job_timeout):
                self._active_scan = asyncio.create_task(
                    self._scanners[job.input.provenance].scan(job.content, job.input.format)
                )
                try:
                    result = await self._active_scan
                finally:
                    self._active_scan = None
            await run_in_threadpool(self._repository.finish, job.id, result)
        except asyncio.CancelledError:
            if not self._closing:
                raise
        except TimeoutError:
            await self._record_failure(job.id, "job_timeout")
        except ScanError as exc:
            await self._record_failure(
                job.id, exc.code if exc.code in _PARSE_ERRORS else "scan_failed"
            )
        except (SQLAlchemyError, TransitionConflict):
            _LOG.warning("Scan storage operation failed")
            await self._record_failure(job.id, "storage_failure")
        except Exception:
            _LOG.warning("Scan processing failed")
            await self._record_failure(job.id, "scan_failed")

    async def _record_failure(self, scan_id: str, error_code: str) -> None:
        try:
            await run_in_threadpool(self._repository.fail, scan_id, error_code)
        except SQLAlchemyError:
            _LOG.warning(
                "Could not record scan failure. Pending scans will be reconciled after restart."
            )
