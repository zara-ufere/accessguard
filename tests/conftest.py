import os
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from accessguard import service
from accessguard.api import create_app
from accessguard.config import Actor
from accessguard.db import init_db, make_engine
from accessguard.models import Base, UserRole

ADMIN = {"Authorization": "Bearer admin-token-1"}
AUDITOR = {"Authorization": "Bearer auditor-token-1"}
TOKENS = {"admin-token-1": Actor("alice", "admin"), "auditor-token-1": Actor("bob", "auditor")}


@pytest.fixture
def engine():
    """Fresh database per test: in-memory SQLite by default, or TEST_DATABASE_URL (PostgreSQL in CI)."""
    eng = make_engine(os.environ.get("TEST_DATABASE_URL", "sqlite://"))
    Base.metadata.drop_all(eng)
    init_db(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def session(engine):
    with Session(engine) as s:
        yield s


@pytest.fixture
def client(engine):
    return TestClient(create_app(engine=engine, tokens=TOKENS))


@pytest.fixture
def world(session):
    return build_world(session)


def build_world(session, actor="tester"):
    """Six permissions, six roles, three rules and three users. No role grants yet.

    Rules: R1 pay.create + pay.approve (critical), R2 code.commit + prod.deploy (high),
    R3 code.commit + db.write (medium).
    """
    w = SimpleNamespace(perms={}, roles={}, rules={}, users={})
    for code in ("pay.create", "pay.approve", "code.commit", "prod.deploy", "db.write", "log.admin"):
        w.perms[code] = service.create_permission(session, actor, code)
    for name, perms in {"Clerk": ["pay.create"], "Approver": ["pay.approve"],
                        "Combo": ["pay.create", "pay.approve"], "Dev": ["code.commit"],
                        "Release": ["prod.deploy"], "DBA": ["db.write"]}.items():
        role = service.create_role(session, actor, name)
        for code in perms:
            service.add_permission_to_role(session, actor, role.id, code)
        w.roles[name] = role
    for code, a, b, severity, control in (("R1", "pay.create", "pay.approve", "critical", "AC-5"),
                                          ("R2", "code.commit", "prod.deploy", "high", "AC-5"),
                                          ("R3", "code.commit", "db.write", "medium", "AC-6")):
        w.rules[code] = service.create_rule(session, actor, code, f"Rule {code}", a, b, severity, control)
    for name in ("ann", "ben", "cy"):
        w.users[name] = service.create_user(session, actor, name, name.title(), "Dept")
    return w


def grant(session, w, user, *role_names):
    """Insert grants directly, the way pre-existing access looks to the tool (no policy check)."""
    for name in role_names:
        session.add(UserRole(user_id=w.users[user].id, role_id=w.roles[name].id, granted_by="legacy"))
    session.flush()


def disable_audit_protection(session):
    """Switch off the append-only trigger so tests can simulate someone tampering with the database."""
    if session.get_bind().dialect.name == "sqlite":
        session.execute(text("DROP TRIGGER audit_log_no_update"))
        session.execute(text("DROP TRIGGER audit_log_no_delete"))
    else:
        session.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_immutable"))
