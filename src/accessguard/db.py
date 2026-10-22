"""Engine and session setup."""
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from .models import GENESIS_HASH, AuditHead, Base


def make_engine(url: str) -> Engine:
    kwargs = {}
    sqlite = url.startswith("sqlite")
    if sqlite:
        kwargs["connect_args"] = {"check_same_thread": False}
        if url in ("sqlite://", "sqlite:///:memory:"):
            kwargs["poolclass"] = StaticPool  # one shared connection keeps the in-memory DB alive
    engine = create_engine(url, **kwargs)
    if sqlite:
        # Recommended pysqlite recipe so SAVEPOINT and foreign keys behave correctly.
        @event.listens_for(engine, "connect")
        def _on_connect(dbapi_connection, _record):
            dbapi_connection.isolation_level = None
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        @event.listens_for(engine, "begin")
        def _on_begin(conn):
            conn.exec_driver_sql("BEGIN")
    return engine


def init_db(engine: Engine) -> None:
    """Create tables (and audit triggers) and the audit head row if they are missing."""
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        if session.get(AuditHead, 1) is None:
            session.add(AuditHead(id=1, last_seq=0, last_hash=GENESIS_HASH))
            try:
                session.commit()
            except IntegrityError:  # another process created it first
                session.rollback()
