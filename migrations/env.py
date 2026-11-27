from alembic import context
from depscope.settings import Settings
from depscope.storage.database import database_path, sqlite_engine, worker_lock
from depscope.storage.models import Base
from sqlalchemy.engine import Connection


def migrate(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=Base.metadata, transactional_ddl=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations() -> None:
    supplied = context.config.attributes.get("connection")
    if isinstance(supplied, Connection):
        migrate(supplied)
        return
    path = database_path(Settings.load().database_path)
    if context.is_offline_mode():
        context.configure(
            dialect_name="sqlite", target_metadata=Base.metadata, transactional_ddl=True
        )
        with context.begin_transaction():
            context.run_migrations()
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with worker_lock(path):
        engine = sqlite_engine(path)
        try:
            with engine.connect() as connection:
                migrate(connection)
        finally:
            engine.dispose()


run_migrations()
