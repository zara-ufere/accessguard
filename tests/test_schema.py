import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError

from accessguard import service
from accessguard.models import AuditHead, SodRule, User, UserRole, utcnow
from conftest import build_world, grant


def test_duplicate_username_is_rejected_by_the_database(session):
    session.add(User(username="x", full_name="X"))
    session.flush()
    session.add(User(username="x", full_name="Other"))
    with pytest.raises(IntegrityError):
        session.flush()


def test_invalid_user_status_is_rejected(session):
    session.add(User(username="x", full_name="X", status="banana"))
    with pytest.raises(IntegrityError):
        session.flush()


def test_a_role_cannot_be_actively_granted_twice_but_can_be_regranted_after_revocation(session, world):
    grant(session, world, "ann", "Clerk")
    session.add(UserRole(user_id=world.users["ann"].id, role_id=world.roles["Clerk"].id, granted_by="x"))
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()

    w = build_world(session)  # rebuild after rollback
    grant(session, w, "ann", "Clerk")
    service.revoke_role(session, "t", w.users["ann"].id, w.roles["Clerk"].id)
    grant(session, w, "ann", "Clerk")  # allowed: the earlier grant is revoked
    rows = session.query(UserRole).filter_by(user_id=w.users["ann"].id).count()
    assert rows == 2


def test_rule_pair_must_be_in_canonical_order(session, world):
    low, high = world.perms["pay.create"].id, world.perms["log.admin"].id
    session.add(SodRule(code="BAD", name="Backwards", permission_a_id=high, permission_b_id=low,
                        severity="low", nist_control="AC-5"))
    with pytest.raises(IntegrityError):
        session.flush()


def test_rule_pair_must_be_unique(session, world):
    a, b = world.perms["pay.create"].id, world.perms["pay.approve"].id
    session.add(SodRule(code="DUP", name="Duplicate", permission_a_id=a, permission_b_id=b,
                        severity="low", nist_control="AC-5"))
    with pytest.raises(IntegrityError):
        session.flush()


def test_rule_severity_is_checked(session, world):
    a, b = world.perms["pay.create"].id, world.perms["log.admin"].id
    session.add(SodRule(code="SEV", name="Bad severity", permission_a_id=a, permission_b_id=b,
                        severity="extreme", nist_control="AC-5"))
    with pytest.raises(IntegrityError):
        session.flush()


def test_foreign_keys_are_enforced(session):
    session.add(UserRole(user_id=9999, role_id=9999, granted_by="x"))
    with pytest.raises(IntegrityError):
        session.flush()


def test_audit_head_is_a_single_row(session):
    session.add(AuditHead(id=2, last_seq=0, last_hash="0" * 64))
    with pytest.raises(IntegrityError):
        session.flush()


def test_audit_entries_cannot_be_updated(session, world):
    session.commit()
    with pytest.raises(DBAPIError, match="append-only"):
        session.execute(text("UPDATE audit_log SET actor = 'mallory' WHERE seq = 1"))


def test_audit_entries_cannot_be_deleted(session, world):
    session.commit()
    with pytest.raises(DBAPIError, match="append-only"):
        session.execute(text("DELETE FROM audit_log WHERE seq = 1"))


def test_second_live_violation_for_same_user_and_rule_is_rejected(session, world):
    from accessguard.models import Violation
    grant(session, world, "ann", "Clerk", "Approver")
    from accessguard.sod import scan
    scan(session, "t")
    existing = session.query(Violation).one()
    session.add(Violation(user_id=existing.user_id, rule_id=existing.rule_id, status="open",
                          detected_at=utcnow(), last_seen_at=utcnow()))
    with pytest.raises(IntegrityError):
        session.flush()
