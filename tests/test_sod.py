import pytest
from sqlalchemy import select

from accessguard import service
from accessguard.models import AuditLog, UserRole, Violation
from accessguard.sod import find_conflicts, scan, would_conflict
from conftest import grant


def roles_of(conflict):
    return set(conflict.roles_a) | set(conflict.roles_b)


def audit_count(session):
    return len(session.scalars(select(AuditLog)).all())


# ---- detection ---------------------------------------------------------------------

def test_conflict_is_found_across_two_roles(session, world):
    grant(session, world, "ann", "Clerk", "Approver")
    (conflict,) = find_conflicts(session)
    assert (conflict.rule_code, conflict.severity) == ("R1", "critical")
    assert roles_of(conflict) == {"Clerk", "Approver"}


def test_conflict_inside_a_single_role_is_found(session, world):
    grant(session, world, "ann", "Combo")
    (conflict,) = find_conflicts(session)
    assert conflict.rule_code == "R1" and roles_of(conflict) == {"Combo"}


def test_one_side_of_a_rule_is_not_a_conflict(session, world):
    grant(session, world, "ann", "Clerk")
    grant(session, world, "ben", "Approver")  # different people: this is the whole point of the rule
    assert find_conflicts(session) == []


def test_overlapping_roles_still_give_one_conflict_per_user_and_rule(session, world):
    grant(session, world, "ann", "Clerk", "Combo", "Approver")
    conflicts = find_conflicts(session)
    assert len(conflicts) == 1
    assert roles_of(conflicts[0]) == {"Clerk", "Combo", "Approver"}


def test_revoked_grants_do_not_count(session, world):
    grant(session, world, "ann", "Clerk", "Approver")
    service.revoke_role(session, "t", world.users["ann"].id, world.roles["Approver"].id)
    assert find_conflicts(session) == []


def test_inactive_rules_are_ignored(session, world):
    grant(session, world, "ann", "Clerk", "Approver")
    service.set_rule_active(session, "t", world.rules["R1"].id, False)
    assert find_conflicts(session) == []


def test_disabled_users_are_ignored(session, world):
    grant(session, world, "ann", "Clerk", "Approver")
    service.disable_user(session, "t", world.users["ann"].id)
    assert find_conflicts(session) == []


def test_user_filter_limits_results(session, world):
    grant(session, world, "ann", "Clerk", "Approver")
    grant(session, world, "ben", "Dev", "Release")
    assert {c.rule_code for c in find_conflicts(session)} == {"R1", "R2"}
    assert {c.rule_code for c in find_conflicts(session, world.users["ben"].id)} == {"R2"}


def test_one_user_can_break_several_rules(session, world):
    grant(session, world, "cy", "Dev", "Release", "DBA")
    assert {c.rule_code for c in find_conflicts(session)} == {"R2", "R3"}


# ---- scans and the violation lifecycle ---------------------------------------------

def test_scan_opens_violations_and_is_idempotent(session, world):
    grant(session, world, "ann", "Clerk", "Approver")
    grant(session, world, "ben", "Dev", "Release")
    first = scan(session, "t")
    assert (first.created, first.refreshed, first.closed) == (2, 0, 0)
    second = scan(session, "t")
    assert (second.created, second.refreshed, second.closed) == (0, 2, 0)
    assert session.query(Violation).count() == 2


def test_scan_closes_violations_when_access_is_removed_and_reopens_a_new_one_on_regrant(session, world):
    grant(session, world, "ann", "Clerk", "Approver")
    scan(session, "t")
    service.revoke_role(session, "t", world.users["ann"].id, world.roles["Approver"].id)
    (violation,) = session.scalars(select(Violation)).all()
    assert violation.status == "remediated" and violation.resolution_note == "No longer detected"

    grant(session, world, "ann", "Approver")
    result = scan(session, "t")
    assert result.created == 1
    statuses = sorted(v.status for v in session.scalars(select(Violation)))
    assert statuses == ["open", "remediated"]  # history kept, new live violation opened


def test_accepted_violations_stay_accepted_across_scans(session, world):
    grant(session, world, "ann", "Clerk", "Approver")
    scan(session, "t")
    violation = session.scalars(select(Violation)).one()
    service.accept_violation(session, "t", violation.id, "Compensating review by the CFO")
    scan(session, "t")
    session.refresh(violation)
    assert violation.status == "accepted"


def test_creating_a_rule_finds_conflicts_that_already_exist(session, world):
    grant(session, world, "cy", "Release", "DBA")
    assert session.query(Violation).count() == 0  # no rule covers this pair yet
    service.create_rule(session, "t", "R4", "Deploy and edit data", "prod.deploy", "db.write", "high")
    (violation,) = session.scalars(select(Violation)).all()
    assert violation.status == "open" and violation.rule.code == "R4"


def test_growing_a_role_creates_violations_for_its_holders(session, world):
    grant(session, world, "ann", "Clerk", "Dev")
    assert session.query(Violation).count() == 0
    service.add_permission_to_role(session, "t", world.roles["Dev"].id, "pay.approve")
    (violation,) = session.scalars(select(Violation)).all()
    assert violation.rule.code == "R1"


def test_deactivating_a_rule_closes_its_violations(session, world):
    grant(session, world, "ann", "Clerk", "Approver")
    scan(session, "t")
    service.set_rule_active(session, "t", world.rules["R1"].id, False)
    assert session.scalars(select(Violation)).one().status == "remediated"


# ---- preventive control: preview and assignment -------------------------------------

def test_preview_reports_new_conflicts_and_saves_nothing(session, world):
    grant(session, world, "ann", "Clerk")
    before_grants, before_audit = session.query(UserRole).count(), audit_count(session)
    conflicts = service.preview_assignment(session, world.users["ann"].id, world.roles["Approver"].id)
    assert [c.rule_code for c in conflicts] == ["R1"]
    assert session.query(UserRole).count() == before_grants
    assert audit_count(session) == before_audit


def test_preview_ignores_conflicts_the_user_already_has(session, world):
    grant(session, world, "ann", "Clerk", "Approver")
    assert would_conflict(session, world.users["ann"].id, world.roles["Dev"].id) == []


def test_critical_conflict_is_blocked_without_override_and_leaves_no_trace(session, world):
    grant(session, world, "ann", "Clerk")
    before_audit = audit_count(session)
    with pytest.raises(service.PolicyBlocked) as caught:
        service.assign_role(session, "t", world.users["ann"].id, world.roles["Approver"].id)
    assert caught.value.details[0]["rule"] == "R1"
    assert session.query(UserRole).filter_by(user_id=world.users["ann"].id).count() == 1
    assert audit_count(session) == before_audit


def test_override_needs_a_written_justification(session, world):
    grant(session, world, "ann", "Clerk")
    for bad in (None, "", "short"):
        with pytest.raises(service.Invalid):
            service.assign_role(session, "t", world.users["ann"].id, world.roles["Approver"].id,
                                justification=bad, override=True)


def test_override_grants_access_and_records_an_accepted_violation(session, world):
    grant(session, world, "ann", "Clerk")
    service.assign_role(session, "t", world.users["ann"].id, world.roles["Approver"].id,
                        justification="Two-person team, CFO reviews weekly", override=True)
    violation = session.scalars(select(Violation)).one()
    assert violation.status == "accepted"
    assert violation.resolution_note == "Two-person team, CFO reviews weekly"
    entry = session.scalars(select(AuditLog).where(AuditLog.action == "role.assigned")
                            .order_by(AuditLog.seq.desc())).first()
    assert '"override":true' in entry.details


def test_medium_conflict_is_allowed_without_override_but_flagged_open(session, world):
    grant(session, world, "cy", "Dev")
    _, conflicts = service.assign_role(session, "t", world.users["cy"].id, world.roles["DBA"].id)
    assert [c.rule_code for c in conflicts] == ["R3"]
    assert session.scalars(select(Violation)).one().status == "open"


def test_clean_assignment_has_no_conflicts(session, world):
    _, conflicts = service.assign_role(session, "t", world.users["ann"].id, world.roles["Clerk"].id)
    assert conflicts == []


def test_duplicate_assignment_is_rejected(session, world):
    service.assign_role(session, "t", world.users["ann"].id, world.roles["Clerk"].id)
    with pytest.raises(service.Duplicate):
        service.assign_role(session, "t", world.users["ann"].id, world.roles["Clerk"].id)


def test_disabled_user_cannot_receive_roles(session, world):
    service.disable_user(session, "t", world.users["ann"].id)
    with pytest.raises(service.Invalid):
        service.assign_role(session, "t", world.users["ann"].id, world.roles["Clerk"].id)


def test_unknown_user_and_role_are_not_found(session, world):
    with pytest.raises(service.NotFound):
        service.assign_role(session, "t", 9999, world.roles["Clerk"].id)
    with pytest.raises(service.NotFound):
        service.assign_role(session, "t", world.users["ann"].id, 9999)


def test_revoking_a_role_that_is_not_held_is_not_found(session, world):
    with pytest.raises(service.NotFound):
        service.revoke_role(session, "t", world.users["ann"].id, world.roles["Clerk"].id)


# ---- accepting risk and rule validation --------------------------------------------

def test_accepting_needs_justification_and_cannot_be_repeated(session, world):
    grant(session, world, "ann", "Clerk", "Approver")
    scan(session, "t")
    violation = session.scalars(select(Violation)).one()
    with pytest.raises(service.Invalid):
        service.accept_violation(session, "t", violation.id, "too short")
    service.accept_violation(session, "t", violation.id, "Documented compensating control")
    with pytest.raises(service.Duplicate):
        service.accept_violation(session, "t", violation.id, "Documented compensating control")
    with pytest.raises(service.NotFound):
        service.accept_violation(session, "t", 9999, "Documented compensating control")


def test_rule_permissions_are_stored_in_canonical_order_and_reversed_pairs_are_duplicates(session, world):
    rule = service.create_rule(session, "t", "R9", "Reversed input", "log.admin", "pay.create", "low")
    assert rule.permission_a_id < rule.permission_b_id
    with pytest.raises(service.Duplicate):
        service.create_rule(session, "t", "R10", "Same pair again", "pay.create", "log.admin", "low")


def test_rule_needs_two_different_permissions(session, world):
    with pytest.raises(service.Invalid):
        service.create_rule(session, "t", "R9", "Same twice", "pay.create", "pay.create", "low")


def test_duplicate_names_are_rejected(session, world):
    with pytest.raises(service.Duplicate):
        service.create_user(session, "t", "ann", "Another Ann")
    with pytest.raises(service.Duplicate):
        service.create_role(session, "t", "Clerk")
    with pytest.raises(service.Duplicate):
        service.create_permission(session, "t", "pay.create")
