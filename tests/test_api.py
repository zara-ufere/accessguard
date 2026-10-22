import pytest

from accessguard.models import AuditLog
from sqlalchemy.orm import Session
from conftest import ADMIN, AUDITOR, disable_audit_protection


def post(client, path, body=None, headers=ADMIN):
    return client.post(path, json=body or {}, headers=headers)


@pytest.fixture
def org(client):
    """Permissions, roles, one critical rule and two users, all created through the API."""
    ids = {}
    for code in ("pay.create", "pay.approve", "code.commit"):
        assert post(client, "/permissions", {"code": code}).status_code == 201
    for name, code in (("Clerk", "pay.create"), ("Approver", "pay.approve"), ("Dev", "code.commit")):
        ids[name] = post(client, "/roles", {"name": name}).json()["id"]
        assert post(client, f"/roles/{ids[name]}/permissions", {"permission_code": code}).status_code == 201
    rule = post(client, "/sod-rules", {"code": "SOD-1", "name": "Create and approve payments",
                                      "permission_a": "pay.create", "permission_b": "pay.approve",
                                      "severity": "critical", "nist_control": "AC-5"})
    assert rule.status_code == 201
    ids["rule"] = rule.json()["id"]
    for name in ("ann", "ben"):
        ids[name] = post(client, "/users", {"username": name, "full_name": name.title(),
                                           "department": "Finance"}).json()["id"]
    return ids


# ---- authentication and authorisation ------------------------------------------------

def test_health_needs_no_token(client):
    assert client.get("/health").json()["status"] == "ok"


def test_dashboard_page_is_served(client):
    response = client.get("/")
    assert response.status_code == 200 and "AccessGuard" in response.text


@pytest.mark.parametrize("path", ["/users", "/roles", "/violations", "/reports/risk", "/audit", "/audit/verify"])
def test_reads_need_a_token(client, path):
    assert client.get(path).status_code == 401
    assert client.get(path, headers={"Authorization": "Bearer wrong-token-0"}).status_code == 401


def test_auditor_can_read_but_not_change(client, org):
    assert client.get("/users", headers=AUDITOR).status_code == 200
    assert client.get("/reports/risk", headers=AUDITOR).status_code == 200
    assert post(client, "/users", {"username": "zed", "full_name": "Zed"}, AUDITOR).status_code == 403
    assert post(client, "/scans", headers=AUDITOR).status_code == 403
    assert client.delete(f"/users/{org['ann']}/roles/{org['Clerk']}", headers=AUDITOR).status_code == 403


# ---- validation and errors -----------------------------------------------------------

@pytest.mark.parametrize("body", [{"username": "Bad Name", "full_name": "x"}, {"username": "a", "full_name": "x"},
                                  {"username": "okname", "full_name": ""}])
def test_invalid_users_are_rejected(client, body):
    assert post(client, "/users", body).status_code == 422


def test_invalid_rule_severity_is_rejected(client, org):
    body = {"code": "X1", "name": "Rule", "permission_a": "pay.create", "permission_b": "code.commit",
            "severity": "extreme"}
    assert post(client, "/sod-rules", body).status_code == 422


def test_duplicates_and_missing_things_return_clear_errors(client, org):
    assert post(client, "/users", {"username": "ann", "full_name": "Again"}).status_code == 409
    assert client.get("/users/9999", headers=ADMIN).status_code == 404
    assert post(client, "/users/9999/roles", {"role_id": org["Clerk"]}).status_code == 404
    assert post(client, "/roles/9999/permissions", {"permission_code": "pay.create"}).status_code == 404
    assert post(client, f"/roles/{org['Clerk']}/permissions", {"permission_code": "nope.nope"}).status_code == 404
    assert client.delete(f"/users/{org['ann']}/roles/{org['Clerk']}", headers=ADMIN).status_code == 404


def test_list_parameters_are_validated(client):
    assert client.get("/violations?status=nonsense", headers=ADMIN).status_code == 422
    assert client.get("/audit?limit=0", headers=ADMIN).status_code == 422
    assert client.get("/users?limit=100000", headers=ADMIN).status_code == 422


# ---- the main workflow ---------------------------------------------------------------

def test_full_workflow(client, org):
    ann = org["ann"]
    assert post(client, f"/users/{ann}/roles", {"role_id": org["Clerk"]}).status_code == 201

    preview = post(client, f"/users/{ann}/roles/preview", {"role_id": org["Approver"]}, AUDITOR).json()
    assert preview["requires_override"] and preview["conflicts"][0]["rule"] == "SOD-1"
    assert [r["name"] for r in client.get(f"/users/{ann}", headers=ADMIN).json()["roles"]] == ["Clerk"]  # preview saved nothing

    blocked = post(client, f"/users/{ann}/roles", {"role_id": org["Approver"]})
    assert blocked.status_code == 409 and blocked.json()["conflicts"][0]["severity"] == "critical"

    weak = post(client, f"/users/{ann}/roles", {"role_id": org["Approver"], "override": True, "justification": "x"})
    assert weak.status_code == 422

    ok = post(client, f"/users/{ann}/roles", {"role_id": org["Approver"], "override": True,
                                              "justification": "CFO reviews every payment weekly"})
    assert ok.status_code == 201 and ok.json()["new_conflicts"][0]["rule"] == "SOD-1"

    (violation,) = client.get("/violations", headers=AUDITOR).json()
    assert violation["status"] == "accepted" and violation["username"] == "ann"
    assert violation["resolution_note"] == "CFO reviews every payment weekly"

    detail = client.get(f"/users/{ann}", headers=ADMIN).json()
    assert detail["permissions"] == ["pay.approve", "pay.create"]

    assert client.delete(f"/users/{ann}/roles/{org['Approver']}?reason=cleanup", headers=ADMIN).status_code == 204
    (closed,) = client.get("/violations?status=remediated", headers=AUDITOR).json()
    assert closed["id"] == violation["id"]
    assert client.get("/violations?status=open", headers=AUDITOR).json() == []


def test_scan_accept_and_filters(client, engine, org):
    from accessguard.models import UserRole
    with Session(engine) as s:  # legacy access that bypassed the tool
        s.add_all([UserRole(user_id=org["ben"], role_id=org["Clerk"], granted_by="legacy"),
                   UserRole(user_id=org["ben"], role_id=org["Approver"], granted_by="legacy")])
        s.commit()
    assert post(client, "/scans").json() == {"created": 1, "refreshed": 0, "closed": 0}
    assert post(client, "/scans").json() == {"created": 0, "refreshed": 1, "closed": 0}

    (violation,) = client.get("/violations?severity=critical&status=open", headers=AUDITOR).json()
    assert client.get("/violations?severity=low", headers=AUDITOR).json() == []
    assert client.get(f"/violations?user_id={org['ann']}", headers=AUDITOR).json() == []

    assert post(client, f"/violations/{violation['id']}/accept", {"justification": "short"}).status_code == 422
    accepted = post(client, f"/violations/{violation['id']}/accept", {"justification": "Approved by the risk committee"})
    assert accepted.status_code == 200 and accepted.json()["status"] == "accepted"
    assert post(client, f"/violations/{violation['id']}/accept", {"justification": "Approved by the risk committee"}).status_code == 409


def test_disabling_a_user_and_toggling_a_rule(client, engine, org):
    from accessguard.models import UserRole
    with Session(engine) as s:
        s.add_all([UserRole(user_id=org["ann"], role_id=org["Clerk"], granted_by="legacy"),
                   UserRole(user_id=org["ann"], role_id=org["Approver"], granted_by="legacy")])
        s.commit()
    post(client, "/scans")
    assert len(client.get("/violations?status=open", headers=ADMIN).json()) == 1
    assert post(client, f"/sod-rules/{org['rule']}/active", {"active": False}).json()["active"] is False
    assert client.get("/violations?status=open", headers=ADMIN).json() == []
    post(client, f"/sod-rules/{org['rule']}/active", {"active": True})
    assert len(client.get("/violations?status=open", headers=ADMIN).json()) == 1
    assert post(client, f"/users/{org['ann']}/disable").json()["status"] == "disabled"
    assert client.get("/violations?status=open", headers=ADMIN).json() == []
    assert post(client, f"/users/{org['ann']}/disable").status_code == 422


def test_risk_report_and_csv(client, engine, org):
    from accessguard.models import UserRole
    with Session(engine) as s:
        s.add_all([UserRole(user_id=org["ben"], role_id=org["Clerk"], granted_by="legacy"),
                   UserRole(user_id=org["ben"], role_id=org["Approver"], granted_by="legacy")])
        s.commit()
    post(client, "/scans")
    report = client.get("/reports/risk", headers=AUDITOR).json()
    assert report["totals"]["open"] == 1 and report["by_severity"]["critical"]["open"] == 1
    assert report["users"][0]["username"] == "ben" and report["users"][0]["score"] == 10.0
    assert report["by_control"][0]["control"] == "AC-5"

    response = client.get("/reports/exceptions.csv", headers=AUDITOR)
    assert response.headers["content-type"].startswith("text/csv")
    lines = response.text.strip().splitlines()
    assert lines[0].startswith("violation_id,username") and "Separation of Duties" in lines[1]


def test_csv_neutralises_spreadsheet_formulas(client, engine):
    from accessguard.models import UserRole
    for code in ("pay.create", "pay.approve"):
        post(client, "/permissions", {"code": code})
    clerk = post(client, "/roles", {"name": "Clerk"}).json()["id"]
    approver = post(client, "/roles", {"name": "Approver"}).json()["id"]
    post(client, f"/roles/{clerk}/permissions", {"permission_code": "pay.create"})
    post(client, f"/roles/{approver}/permissions", {"permission_code": "pay.approve"})
    post(client, "/sod-rules", {"code": "S1", "name": "Create and approve", "permission_a": "pay.create",
                                "permission_b": "pay.approve", "severity": "high"})
    user = post(client, "/users", {"username": "eve", "full_name": "Eve", "department": "=HYPERLINK(\"http://evil\")"}).json()["id"]
    with Session(engine) as s:
        s.add_all([UserRole(user_id=user, role_id=clerk, granted_by="l"), UserRole(user_id=user, role_id=approver, granted_by="l")])
        s.commit()
    post(client, "/scans")
    text = client.get("/reports/exceptions.csv", headers=ADMIN).text
    assert "'=HYPERLINK" in text and ",=HYPERLINK" not in text


def test_audit_endpoints(client, engine, org):
    verify = client.get("/audit/verify", headers=AUDITOR).json()
    assert verify["ok"] and verify["checked"] == verify["head_seq"] > 5
    entries = client.get("/audit?limit=3", headers=AUDITOR).json()
    assert [e["seq"] for e in entries] == [verify["head_seq"], verify["head_seq"] - 1, verify["head_seq"] - 2]
    assert entries[0]["actor"] == "alice"  # the admin token's identity is what gets recorded

    with Session(engine) as s:
        disable_audit_protection(s)
        s.query(AuditLog).filter_by(seq=2).update({"actor": "mallory"})
        s.commit()
    broken = client.get("/audit/verify", headers=AUDITOR).json()
    assert broken["ok"] is False and broken["first_bad_seq"] == 2
