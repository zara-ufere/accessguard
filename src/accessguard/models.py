"""Database schema.

Integrity rules live in the database, not only in Python: unique and check
constraints, foreign keys, partial unique indexes, and triggers that make the
audit log append-only.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import (JSON, Boolean, CheckConstraint, DateTime, DDL, ForeignKey, Index,
                        Integer, String, Text, UniqueConstraint, event, text)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

GENESIS_HASH = "0" * 64
SEVERITIES = ("low", "medium", "high", "critical")


def utcnow() -> datetime:
    """Naive UTC timestamp. Every datetime in the database is UTC."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(128), nullable=False)
    department: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    __table_args__ = (CheckConstraint("status IN ('active','disabled')", name="ck_users_status"),)


class Permission(Base):
    __tablename__ = "permissions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=False, default="")


class Role(Base):
    __tablename__ = "roles"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    permissions = relationship("Permission", secondary="role_permissions",
                               order_by="Permission.code", viewonly=True)


class RolePermission(Base):
    __tablename__ = "role_permissions"
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    permission_id: Mapped[int] = mapped_column(ForeignKey("permissions.id", ondelete="CASCADE"),
                                               primary_key=True)
    __table_args__ = (Index("ix_role_permissions_permission", "permission_id"),)


class UserRole(Base):
    """One row per grant. Revoking sets revoked_at, so access history is never lost."""
    __tablename__ = "user_roles"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), nullable=False)
    granted_by: Mapped[str] = mapped_column(String(64), nullable=False)
    granted_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    justification: Mapped[Optional[str]] = mapped_column(Text)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    revoked_by: Mapped[Optional[str]] = mapped_column(String(64))
    user = relationship("User")
    role = relationship("Role")
    __table_args__ = (
        # A user can hold a role at most once at a time, but can be re-granted later.
        Index("uq_user_roles_active", "user_id", "role_id", unique=True,
              sqlite_where=text("revoked_at IS NULL"), postgresql_where=text("revoked_at IS NULL")),
    )


class SodRule(Base):
    """A pair of permissions no single person should hold together.

    The pair is stored in canonical order (a < b) so (A,B) and (B,A) cannot both exist.
    """
    __tablename__ = "sod_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    permission_a_id: Mapped[int] = mapped_column(ForeignKey("permissions.id"), nullable=False)
    permission_b_id: Mapped[int] = mapped_column(ForeignKey("permissions.id"), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    nist_control: Mapped[str] = mapped_column(String(16), nullable=False, default="AC-5")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    permission_a = relationship("Permission", foreign_keys=[permission_a_id])
    permission_b = relationship("Permission", foreign_keys=[permission_b_id])
    __table_args__ = (
        UniqueConstraint("permission_a_id", "permission_b_id", name="uq_sod_rules_pair"),
        CheckConstraint("permission_a_id < permission_b_id", name="ck_sod_rules_canonical_order"),
        CheckConstraint("severity IN ('low','medium','high','critical')", name="ck_sod_rules_severity"),
    )


class Violation(Base):
    """A detected conflict for one user and one rule, with a lifecycle."""
    __tablename__ = "violations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    rule_id: Mapped[int] = mapped_column(ForeignKey("sod_rules.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    detected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    resolved_by: Mapped[Optional[str]] = mapped_column(String(64))
    resolution_note: Mapped[Optional[str]] = mapped_column(Text)
    evidence: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    user = relationship("User")
    rule = relationship("SodRule")
    __table_args__ = (
        CheckConstraint("status IN ('open','accepted','remediated')", name="ck_violations_status"),
        # At most one live (not remediated) violation per user and rule.
        Index("uq_violations_live", "user_id", "rule_id", unique=True,
              sqlite_where=text("status <> 'remediated'"),
              postgresql_where=text("status <> 'remediated'")),
        Index("ix_violations_status", "status"),
    )


class AuditLog(Base):
    """Append-only, hash-chained record of every change."""
    __tablename__ = "audit_log"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    ts: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)


class AuditHead(Base):
    """Single row holding the newest audit entry. Locking it serializes audit writes."""
    __tablename__ = "audit_head"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    last_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    last_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    __table_args__ = (CheckConstraint("id = 1", name="ck_audit_head_single_row"),)


# Triggers that reject UPDATE and DELETE on audit_log (one flavor per database).
_SQLITE_NO_UPDATE = DDL(
    "CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log "
    "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END")
_SQLITE_NO_DELETE = DDL(
    "CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log "
    "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END")
_PG_FUNCTION = DDL(
    "CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$ "
    "BEGIN RAISE EXCEPTION 'audit_log is append-only'; END; $$ LANGUAGE plpgsql")
_PG_TRIGGER = DDL(
    "CREATE TRIGGER audit_log_immutable BEFORE UPDATE OR DELETE ON audit_log "
    "FOR EACH ROW EXECUTE FUNCTION audit_log_immutable()")

for _ddl in (_SQLITE_NO_UPDATE, _SQLITE_NO_DELETE):
    event.listen(AuditLog.__table__, "after_create", _ddl.execute_if(dialect="sqlite"))
for _ddl in (_PG_FUNCTION, _PG_TRIGGER):
    event.listen(AuditLog.__table__, "after_create", _ddl.execute_if(dialect="postgresql"))
