import pytest

from accessguard import reports, service
from accessguard.models import Violation
from accessguard.sod import scan
from conftest import grant


@pytest.mark.parametrize("score,label", [(0, "None"), (0.5, "Low"), (4.9, "Low"), (5, "Medium"),
                                         (9.9, "Medium"), (10, "High"), (19.9, "High"), (20, "Critical")])
def test_rating_boundaries(score, label):
    assert reports.rating(score) == label


@pytest.mark.parametrize("value,expected", [("=1+1", "'=1+1"), ("+x", "'+x"), ("-x", "'-x"), ("@x", "'@x"),
                                            ("plain", "plain"), (None, ""), (5, "5")])
def test_safe_cell(value, expected):
    assert reports._safe_cell(value) == expected


def test_empty_report(session):
    report = reports.risk_report(session)
    assert report["totals"] == {"open": 0, "accepted": 0, "remediated": 0}
    assert report["users"] == [] and report["by_control"] == []
    assert all(v == {"open": 0, "accepted": 0} for v in report["by_severity"].values())


def test_scores_and_totals(session, world):
    # ann: critical open (10) + high open (5)           = 15.0
    # ben: medium accepted (2 * 0.5)                    = 1.0
    # cy : high accepted (5 * 0.5) + nothing else        = 2.5
    grant(session, world, "ann", "Clerk", "Approver", "Dev", "Release")
    grant(session, world, "ben", "Dev", "DBA")
    grant(session, world, "cy", "Dev", "Release")
    scan(session, "t")
    by_key = {(v.user.username, v.rule.code): v for v in session.query(Violation)}
    service.accept_violation(session, "t", by_key[("ben", "R3")].id, "Reviewed by the engineering director")
    service.accept_violation(session, "t", by_key[("cy", "R2")].id, "Reviewed by the engineering director")
    report = reports.risk_report(session)

    assert report["totals"] == {"open": 2, "accepted": 2, "remediated": 0}
    scores = {u["username"]: (u["score"], u["rating"], u["open"], u["accepted"]) for u in report["users"]}
    assert scores == {"ann": (15.0, "High", 2, 0), "cy": (2.5, "Low", 0, 1), "ben": (1.0, "Low", 0, 1)}
    assert [u["username"] for u in report["users"]] == ["ann", "cy", "ben"]  # highest risk first

    assert report["by_severity"] == {"low": {"open": 0, "accepted": 0}, "medium": {"open": 0, "accepted": 1},
                                     "high": {"open": 1, "accepted": 1}, "critical": {"open": 1, "accepted": 0}}
    controls = {c["control"]: (c["open"], c["accepted"], c["score"]) for c in report["by_control"]}
    assert controls == {"AC-5": (2, 1, 17.5), "AC-6": (0, 1, 1.0)}
    assert report["by_control"][0]["title"] == "Separation of Duties"


def test_remediated_violations_do_not_count_toward_risk(session, world):
    grant(session, world, "ann", "Clerk", "Approver")
    scan(session, "t")
    service.revoke_role(session, "t", world.users["ann"].id, world.roles["Approver"].id)
    report = reports.risk_report(session)
    assert report["totals"] == {"open": 0, "accepted": 0, "remediated": 1}
    assert report["users"] == []


def test_csv_hides_remediated_unless_asked(session, world):
    grant(session, world, "ann", "Clerk", "Approver")
    scan(session, "t")
    service.revoke_role(session, "t", world.users["ann"].id, world.roles["Approver"].id)
    assert len(reports.exceptions_csv(session).strip().splitlines()) == 1  # header only
    full = reports.exceptions_csv(session, include_remediated=True).strip().splitlines()
    assert len(full) == 2 and "remediated" in full[1] and "Critical" in full[1]
