import pytest
from sqlalchemy import select, text

from accessguard import audit, service
from accessguard.models import AuditHead, AuditLog, GENESIS_HASH
from conftest import disable_audit_protection, grant


def test_hash_format_is_pinned():
    # If this changes, every existing audit chain stops verifying. Change it deliberately.
    assert audit.compute_hash(GENESIS_HASH, 1, "2026-01-01T00:00:00.000000Z", "alice", "user.created",
                              "user", "1", '{"a":1}') == \
        "1e2c6803e7d3496f6a9868698d4c2c944031d91ed830bd91f024688150e5eefe"


@pytest.mark.parametrize("field,value", [("prev_hash", "f" * 64), ("seq", 2), ("ts", "2026-01-02"),
                                         ("actor", "mallory"), ("action", "user.deleted"),
                                         ("entity_type", "role"), ("entity_id", "2"), ("details", "{}")])
def test_changing_any_field_changes_the_hash(field, value):
    base = dict(prev_hash=GENESIS_HASH, seq=1, ts="2026-01-01", actor="a", action="x",
                entity_type="user", entity_id="1", details='{"a":1}')
    changed = dict(base, **{field: value})
    assert audit.compute_hash(**base) != audit.compute_hash(**changed)


def test_empty_log_verifies(session):
    result = audit.verify(session)
    assert result.ok and result.checked == 0 and result.head_hash == GENESIS_HASH


def test_normal_use_produces_a_valid_linked_chain(session, world):
    grant(session, world, "ann", "Clerk", "Approver")
    service.assign_role(session, "t", world.users["ben"].id, world.roles["Dev"].id)
    result = audit.verify(session)
    assert result.ok and result.checked == result.head_seq > 10
    rows = session.scalars(select(AuditLog).order_by(AuditLog.seq)).all()
    assert rows[0].prev_hash == GENESIS_HASH
    for before, after in zip(rows, rows[1:]):
        assert after.prev_hash == before.hash and after.seq == before.seq + 1


def test_altering_an_entry_is_detected_at_that_entry(session, world):
    session.commit()
    disable_audit_protection(session)
    session.execute(text("UPDATE audit_log SET actor = 'mallory' WHERE seq = 5"))
    session.commit()
    result = audit.verify(session)
    assert not result.ok and result.first_bad_seq == 5 and "altered" in result.problem


def test_altering_details_is_detected(session, world):
    session.commit()
    disable_audit_protection(session)
    session.execute(text("UPDATE audit_log SET details = '{}' WHERE seq = 3"))
    session.commit()
    assert audit.verify(session).first_bad_seq == 3


def test_deleting_a_middle_entry_is_detected(session, world):
    session.commit()
    disable_audit_protection(session)
    session.execute(text("DELETE FROM audit_log WHERE seq = 4"))
    session.commit()
    result = audit.verify(session)
    assert not result.ok and result.first_bad_seq == 5 and "missing" in result.problem


def test_deleting_the_newest_entries_is_detected_through_the_head(session, world):
    session.commit()
    disable_audit_protection(session)
    last = audit.verify(session).head_seq
    session.execute(text(f"DELETE FROM audit_log WHERE seq = {last}"))
    session.commit()
    result = audit.verify(session)
    assert not result.ok and "head" in result.problem


def test_a_rewritten_head_is_detected(session, world):
    session.commit()
    head = session.get(AuditHead, 1)
    head.last_hash = "a" * 64
    session.commit()
    assert not audit.verify(session).ok


def test_audit_entry_rolls_back_with_the_change(session):
    service.create_user(session, "t", "temp", "Temp User")
    session.rollback()
    assert session.scalars(select(AuditLog)).all() == []
    head = session.get(AuditHead, 1)
    assert (head.last_seq, head.last_hash) == (0, GENESIS_HASH)


def test_blocked_assignment_writes_nothing(session, world):
    grant(session, world, "ann", "Clerk")
    before = audit.verify(session)
    with pytest.raises(service.PolicyBlocked):
        service.assign_role(session, "t", world.users["ann"].id, world.roles["Approver"].id)
    after = audit.verify(session)
    assert (after.ok, after.head_seq, after.head_hash) == (True, before.head_seq, before.head_hash)


def test_entries_record_who_did_what(session):
    user = service.create_user(session, "alice", "dana", "Dana Smith", "IT")
    entry = session.scalars(select(AuditLog).order_by(AuditLog.seq.desc())).first()
    assert (entry.actor, entry.action, entry.entity_type, entry.entity_id) == \
           ("alice", "user.created", "user", str(user.id))
