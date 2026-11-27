import os
from dataclasses import dataclass
from pathlib import Path
from typing import Self
from urllib.parse import urlsplit

_LOCAL_ORIGINS = ("http://127.0.0.1:8000", "http://localhost:8000", "http://[::1]:8000")


@dataclass(frozen=True, slots=True)
class Settings:
    database_path: Path = Path("data/depscope.sqlite3")
    max_file_bytes: int = 1_000_000
    max_pending_jobs: int = 4
    submissions_per_minute: int = 30
    upload_timeout: int = 10
    job_timeout: int = 60
    allowed_origins: tuple[str, ...] = _LOCAL_ORIGINS

    def __post_init__(self) -> None:
        limits = (
            (self.max_file_bytes, 1, 10_000_000),
            (self.max_pending_jobs, 0, 32),
            (self.submissions_per_minute, 1, 600),
            (self.upload_timeout, 1, 120),
            (self.job_timeout, 1, 300),
        )
        if any(not low <= value <= high for value, low, high in limits):
            raise ValueError("DepScope service limits are out of range")
        for origin in self.allowed_origins:
            url = urlsplit(origin)
            if (
                url.scheme not in ("http", "https")
                or url.hostname not in ("localhost", "127.0.0.1", "::1")
                or url.username is not None
                or url.path
                or url.query
                or url.fragment
            ):
                raise ValueError("DepScope browser origins must be loopback HTTP origins")
            _ = url.port

    @classmethod
    def load(cls) -> Self:
        def integer(name: str, default: int) -> int:
            try:
                return int(os.environ.get(name, str(default)))
            except ValueError:
                raise ValueError(f"{name} must be an integer") from None

        extra_origins = os.environ.get("DEPSCOPE_ALLOWED_ORIGINS", "")
        return cls(
            database_path=Path(os.environ.get("DEPSCOPE_DB_PATH", "data/depscope.sqlite3")),
            max_file_bytes=integer("DEPSCOPE_MAX_FILE_BYTES", 1_000_000),
            max_pending_jobs=integer("DEPSCOPE_MAX_PENDING_JOBS", 4),
            submissions_per_minute=integer("DEPSCOPE_SUBMISSIONS_PER_MINUTE", 30),
            upload_timeout=integer("DEPSCOPE_UPLOAD_TIMEOUT", 10),
            job_timeout=integer("DEPSCOPE_JOB_TIMEOUT", 60),
            allowed_origins=_LOCAL_ORIGINS
            + tuple(o.strip() for o in extra_origins.split(",") if o.strip()),
        )
