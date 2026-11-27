import sqlite3
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import URL, Engine, create_engine, event, inspect, text

from .models import Base

SCHEMA_REVISION = "0001_scan_history"


def database_path(path: Path) -> Path:
    resolved = path.resolve()
    if not resolved.is_relative_to(Path.cwd().resolve()) or resolved.suffix.lower() not in {
        ".db",
        ".sqlite",
        ".sqlite3",
    }:
        raise ValueError("The SQLite file must be inside the application workspace")
    return resolved


def sqlite_engine(path: Path) -> Engine:
    engine = create_engine(
        URL.create("sqlite+pysqlite", database=str(path)),
        connect_args={"autocommit": False, "timeout": 1.5},
        hide_parameters=True,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection: sqlite3.Connection, record: object) -> None:
        previous = connection.autocommit
        connection.autocommit = True
        try:
            connection.execute("PRAGMA foreign_keys=ON").close()
        finally:
            connection.autocommit = previous

    return engine


def database_ready(engine: Engine) -> bool:
    with engine.connect() as connection:
        expected_tables = {"alembic_version", *Base.metadata.tables}
        if not expected_tables.issubset(inspect(connection).get_table_names()):
            return False
        revisions = (
            connection.execute(text("SELECT version_num FROM alembic_version")).scalars().all()
        )
        if revisions != [SCHEMA_REVISION]:
            return False
        connection.execute(text("SELECT id FROM scans LIMIT 1"))
        return True


@contextmanager
def worker_lock(path: Path) -> Iterator[None]:
    """Hold a process-owned lock for the API lifespan. The OS releases it after a crash."""
    lock_path = path.with_name(path.name + ".worker.lock")
    if lock_path.is_symlink():
        raise RuntimeError("The scan worker lock cannot be a symbolic link")
    with lock_path.open("a+b") as handle:
        handle.seek(0)
        try:
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise RuntimeError("Another DepScope worker owns this database") from None
        yield
