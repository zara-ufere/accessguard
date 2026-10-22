"""Business operations. Each one validates, changes data, and writes an audit entry
inside the caller's transaction, so a failure leaves no partial change behind."""
from typing import List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .models import (Permission, Role, RolePermission, SodRule, User, UserRole, Violation, utcnow)
from .sod import BLOCKING, Conflict, reconcile, would_conflict


class DomainError(Exception):
    status_code = 400

    def __init__(self, message: str, details=None):
        super().__init__(message)
        self.message = message
        self.details = details


class NotFound(DomainError):
    status_code = 404


class Duplicate(DomainError):
    status_code = 409


class PolicyBlocked(DomainError):
    status_code = 409


class Invalid(DomainError):
    status_code = 422


# ---- lookups -------------------------------------------------------------------------

def get_user(session: Session, user_id: int) -> User:
    user = session.get(User, user_id)
    if user is None:
        raise NotFound(f"User {user_id} does not exist")
    return user


def get_role(session: Session, role_id: int) -> Role:
    role = session.get(Role, role_id)
    if role is None:
        raise NotFound(f"Role {role_id} does not exist")
    return role


def get_permission_by_code(session: Session, code: str) -> Permission:
    permission = session.scalar(select(Permission).where(Permission.code == code))
    if permission is None:
        raise NotFound(f"Permission '{code}' does not exist")
    return permission


def get_rule(session: Session, rule_id: int) -> SodRule:
    rule = session.get(SodRule, rule_id)
    if rule is None:
        raise NotFound(f"Rule {rule_id} does not exist")
    return rule


# ---- catalog -------------------------------------------------------------------------

def create_user(session: Session, actor: str, username: str, full_name: str, department: str = "") -> User:
    if session.scalar(select(User).where(User.username == username)):
        raise Duplicate(f"Username '{username}' is already taken")
    user = User(username=username, full_name=full_name, department=department)
    session.add(user)
    session.flush()
    audit.record(session, actor, "user.created", "user", user.id,
                 {"username": username, "department": department})
    return user


def create_permission(session: Session, actor: str, code: str, description: str = "") -> Permission:
    if session.scalar(select(Permission).where(Permission.code == code)):
        raise Duplicate(f"Permission '{code}' already exists")
    permission = Permission(code=code, description=description)
    session.add(permission)
    session.flush()
    audit.record(session, actor, "permission.created", "permission", permission.id, {"code": code})
    return permission


def create_role(session: Session, actor: str, name: str, description: str = "") -> Role:
    if session.scalar(select(Role).where(Role.name == name)):
        raise Duplicate(f"Role '{name}' already exists")
    role = Role(name=name, description=description)
    session.add(role)
    session.flush()
    audit.record(session, actor, "role.created", "role", role.id, {"name": name})
    return role


def add_permission_to_role(session: Session, actor: str, role_id: int, permission_code: str) -> Role:
    role = get_role(session, role_id)
    permission = get_permission_by_code(session, permission_code)
    if session.get(RolePermission, (role.id, permission.id)):
        raise Duplicate(f"Role '{role.name}' already has '{permission_code}'")
    session.add(RolePermission(role_id=role.id, permission_id=permission.id))
    session.flush()
    session.expire(role, ["permissions"])
    audit.record(session, actor, "role.permission_added", "role", role.id,
                 {"role": role.name, "permission": permission_code})
    reconcile(session, actor)  # a bigger role can create conflicts for everyone holding it
    return role


def create_rule(session: Session, actor: str, code: str, name: str, permission_a: str,
                permission_b: str, severity: str, nist_control: str = "AC-5",
                description: str = "") -> SodRule:
    if session.scalar(select(SodRule).where(SodRule.code == code)):
        raise Duplicate(f"Rule '{code}' already exists")
    pa = get_permission_by_code(session, permission_a)
    pb = get_permission_by_code(session, permission_b)
    if pa.id == pb.id:
        raise Invalid("A rule needs two different permissions")
    low, high = (pa, pb) if pa.id < pb.id else (pb, pa)  # canonical order
    if session.scalar(select(SodRule).where(SodRule.permission_a_id == low.id,
                                            SodRule.permission_b_id == high.id)):
        raise Duplicate("A rule for this pair of permissions already exists")
    rule = SodRule(code=code, name=name, description=description, permission_a_id=low.id,
                   permission_b_id=high.id, severity=severity, nist_control=nist_control)
    session.add(rule)
    session.flush()
    audit.record(session, actor, "rule.created", "rule", rule.id,
                 {"code": code, "severity": severity, "permissions": [low.code, high.code]})
    reconcile(session, actor)
    return rule


def set_rule_active(session: Session, actor: str, rule_id: int, active: bool) -> SodRule:
    rule = get_rule(session, rule_id)
    rule.active = active
    session.flush()
    audit.record(session, actor, "rule.activated" if active else "rule.deactivated", "rule",
                 rule.id, {"code": rule.code})
    reconcile(session, actor)
    return rule


# ---- access changes ------------------------------------------------------------------

def _active_grant(session: Session, user_id: int, role_id: int) -> Optional[UserRole]:
    return session.scalar(select(UserRole).where(
        UserRole.user_id == user_id, UserRole.role_id == role_id, UserRole.revoked_at.is_(None)))


def preview_assignment(session: Session, user_id: int, role_id: int) -> List[Conflict]:
    user, role = get_user(session, user_id), get_role(session, role_id)
    if user.status != "active":
        raise Invalid("Cannot assign roles to a disabled user")
    if _active_grant(session, user.id, role.id):
        raise Duplicate(f"{user.username} already holds '{role.name}'")
    return would_conflict(session, user.id, role.id)


def assign_role(session: Session, actor: str, user_id: int, role_id: int,
                justification: Optional[str] = None, override: bool = False
                ) -> Tuple[UserRole, List[Conflict]]:
    """Grant a role. High and critical conflicts are blocked unless an override with a
    written justification is given; the resulting violation is then recorded as accepted."""
    new_conflicts = preview_assignment(session, user_id, role_id)
    blocking = [c for c in new_conflicts if c.blocking]
    if blocking:
        if not override:
            raise PolicyBlocked(
                "This grant would create a separation of duties conflict that needs an override",
                details=[{"rule": c.rule_code, "name": c.rule_name, "severity": c.severity,
                          "nist_control": c.nist_control, "roles_a": list(c.roles_a),
                          "roles_b": list(c.roles_b)} for c in blocking])
        if not justification or len(justification.strip()) < 10:
            raise Invalid("An override needs a justification of at least 10 characters")
    role = get_role(session, role_id)
    grant = UserRole(user_id=user_id, role_id=role_id, granted_by=actor,
                     justification=justification.strip() if justification else None)
    session.add(grant)
    session.flush()
    audit.record(session, actor, "role.assigned", "user", user_id,
                 {"role": role.name, "override": bool(blocking), "justification": justification,
                  "new_conflicts": [c.rule_code for c in new_conflicts]})
    reconcile(session, actor, user_id)
    for conflict in blocking:
        violation = session.scalar(select(Violation).where(
            Violation.user_id == user_id, Violation.rule_id == conflict.rule_id,
            Violation.status == "open"))
        if violation is not None:
            _accept(session, actor, violation, justification.strip())
    return grant, new_conflicts


def revoke_role(session: Session, actor: str, user_id: int, role_id: int,
                reason: Optional[str] = None) -> UserRole:
    user, role = get_user(session, user_id), get_role(session, role_id)
    grant = _active_grant(session, user.id, role.id)
    if grant is None:
        raise NotFound(f"{user.username} does not currently hold '{role.name}'")
    grant.revoked_at = utcnow()
    grant.revoked_by = actor
    session.flush()
    audit.record(session, actor, "role.revoked", "user", user.id,
                 {"role": role.name, "reason": reason})
    reconcile(session, actor, user.id)
    return grant


def disable_user(session: Session, actor: str, user_id: int) -> User:
    user = get_user(session, user_id)
    if user.status == "disabled":
        raise Invalid(f"{user.username} is already disabled")
    user.status = "disabled"
    session.flush()
    audit.record(session, actor, "user.disabled", "user", user.id, {"username": user.username})
    reconcile(session, actor, user.id)
    return user


# ---- violations ----------------------------------------------------------------------

def _accept(session: Session, actor: str, violation: Violation, justification: str) -> None:
    violation.status = "accepted"
    violation.resolved_at = utcnow()
    violation.resolved_by = actor
    violation.resolution_note = justification
    session.flush()
    audit.record(session, actor, "violation.accepted", "violation", violation.id,
                 {"justification": justification})


def accept_violation(session: Session, actor: str, violation_id: int, justification: str) -> Violation:
    violation = session.get(Violation, violation_id)
    if violation is None:
        raise NotFound(f"Violation {violation_id} does not exist")
    if violation.status != "open":
        raise Duplicate(f"Violation {violation_id} is already {violation.status}")
    if len(justification.strip()) < 10:
        raise Invalid("Accepting a risk needs a justification of at least 10 characters")
    _accept(session, actor, violation, justification.strip())
    return violation
