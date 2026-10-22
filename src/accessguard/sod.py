"""Separation of duties: find users who hold both sides of a rule, and keep violations in sync.

The detection itself is one SQL query: a CTE of each user's effective permissions
(through active role grants) joined to itself once per side of each rule.
"""
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from . import audit
from .models import Role, RolePermission, SodRule, User, UserRole, Violation, utcnow

BLOCKING = ("high", "critical")  # severities that need an override to be granted


@dataclass(frozen=True)
class Conflict:
    user_id: int
    rule_id: int
    rule_code: str
    rule_name: str
    severity: str
    nist_control: str
    roles_a: Tuple[str, ...]
    roles_b: Tuple[str, ...]

    @property
    def blocking(self) -> bool:
        return self.severity in BLOCKING

    @property
    def evidence(self) -> Dict[str, Any]:
        return {"roles_a": list(self.roles_a), "roles_b": list(self.roles_b)}


def find_conflicts(session: Session, user_id: Optional[int] = None) -> List[Conflict]:
    """All current conflicts for active users under active rules (one user if given)."""
    effective = (
        select(UserRole.user_id.label("user_id"), UserRole.role_id.label("role_id"),
               RolePermission.permission_id.label("permission_id"))
        .select_from(UserRole)
        .join(RolePermission, RolePermission.role_id == UserRole.role_id)
        .where(UserRole.revoked_at.is_(None))
    )
    if user_id is not None:
        effective = effective.where(UserRole.user_id == user_id)
    eff = effective.cte("effective")
    side_a, side_b = eff.alias("side_a"), eff.alias("side_b")
    stmt = (
        select(SodRule.id, SodRule.code, SodRule.name, SodRule.severity, SodRule.nist_control,
               side_a.c.user_id, side_a.c.role_id.label("role_a"), side_b.c.role_id.label("role_b"))
        .select_from(SodRule)
        .join(side_a, side_a.c.permission_id == SodRule.permission_a_id)
        .join(side_b, and_(side_b.c.user_id == side_a.c.user_id,
                           side_b.c.permission_id == SodRule.permission_b_id))
        .join(User, User.id == side_a.c.user_id)
        .where(SodRule.active.is_(True), User.status == "active")
    )
    role_names = dict(session.execute(select(Role.id, Role.name)).all())
    grouped: Dict[Tuple[int, int], Dict[str, Any]] = {}
    for rule_id, code, name, severity, control, uid, role_a, role_b in session.execute(stmt):
        entry = grouped.setdefault((uid, rule_id), {
            "code": code, "name": name, "severity": severity, "control": control,
            "a": set(), "b": set()})
        entry["a"].add(role_names[role_a])
        entry["b"].add(role_names[role_b])
    return [
        Conflict(uid, rule_id, e["code"], e["name"], e["severity"], e["control"],
                 tuple(sorted(e["a"])), tuple(sorted(e["b"])))
        for (uid, rule_id), e in sorted(grouped.items())
    ]


def would_conflict(session: Session, user_id: int, role_id: int) -> List[Conflict]:
    """Conflicts that granting this role would newly create. Nothing is saved.

    The grant is added inside a SAVEPOINT, checked with the real detection query,
    then rolled back, so the preview can never disagree with the real check.
    """
    before = {c.rule_id for c in find_conflicts(session, user_id)}
    savepoint = session.begin_nested()
    try:
        session.add(UserRole(user_id=user_id, role_id=role_id, granted_by="(preview)"))
        session.flush()
        after = find_conflicts(session, user_id)
    finally:
        savepoint.rollback()
    return [c for c in after if c.rule_id not in before]


@dataclass
class ScanResult:
    created: int = 0
    refreshed: int = 0
    closed: int = 0


def reconcile(session: Session, actor: str, user_id: Optional[int] = None) -> ScanResult:
    """Bring stored violations in line with what the detection query finds now.

    New conflicts open a violation, still-present ones are refreshed, and ones that
    no longer exist are closed as remediated. Running it twice changes nothing.
    """
    detected = {(c.user_id, c.rule_id): c for c in find_conflicts(session, user_id)}
    query = select(Violation).where(Violation.status != "remediated")
    if user_id is not None:
        query = query.where(Violation.user_id == user_id)
    live = {(v.user_id, v.rule_id): v for v in session.scalars(query)}
    now, result = utcnow(), ScanResult()
    for key, conflict in sorted(detected.items()):
        existing = live.get(key)
        if existing is not None:
            existing.last_seen_at = now
            existing.evidence = conflict.evidence
            result.refreshed += 1
            continue
        violation = Violation(user_id=conflict.user_id, rule_id=conflict.rule_id, status="open",
                              detected_at=now, last_seen_at=now, evidence=conflict.evidence)
        session.add(violation)
        session.flush()
        audit.record(session, actor, "violation.detected", "violation", violation.id,
                     {"user_id": conflict.user_id, "rule": conflict.rule_code,
                      "severity": conflict.severity})
        result.created += 1
    for key, violation in sorted(live.items()):
        if key in detected:
            continue
        violation.status = "remediated"
        violation.resolved_at = now
        violation.resolved_by = actor
        violation.resolution_note = "No longer detected"
        audit.record(session, actor, "violation.auto_closed", "violation", violation.id,
                     {"user_id": violation.user_id, "rule_id": violation.rule_id})
        result.closed += 1
    session.flush()
    return result


def scan(session: Session, actor: str) -> ScanResult:
    """Full rescan of every user, recorded in the audit log."""
    result = reconcile(session, actor)
    audit.record(session, actor, "scan.completed", "system", "scan",
                 {"created": result.created, "refreshed": result.refreshed, "closed": result.closed})
    return result
