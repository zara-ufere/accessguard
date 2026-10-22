"""Risk and exception reporting. Totals are computed in SQL with GROUP BY."""
import csv
import io
from typing import Any, Dict, List

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from .models import SEVERITIES, SodRule, User, Violation, utcnow

LIVE = ("open", "accepted")
SEVERITY_WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 1}
ACCEPTED_FACTOR = 0.5  # an accepted risk still counts, at half weight

# NIST SP 800-53 control titles for the controls the demo rules map to.
NIST_TITLES = {
    "AC-2": "Account Management",
    "AC-5": "Separation of Duties",
    "AC-6": "Least Privilege",
    "AU-9": "Protection of Audit Information",
}


def _weight():
    severity = case((SodRule.severity == "critical", SEVERITY_WEIGHT["critical"]),
                    (SodRule.severity == "high", SEVERITY_WEIGHT["high"]),
                    (SodRule.severity == "medium", SEVERITY_WEIGHT["medium"]),
                    else_=SEVERITY_WEIGHT["low"])
    factor = case((Violation.status == "open", 1.0), else_=ACCEPTED_FACTOR)
    return severity * factor


def rating(score: float) -> str:
    if score <= 0:
        return "None"
    if score < 5:
        return "Low"
    if score < 10:
        return "Medium"
    if score < 20:
        return "High"
    return "Critical"


def risk_report(session: Session) -> Dict[str, Any]:
    totals = {"open": 0, "accepted": 0, "remediated": 0}
    for status, count in session.execute(select(Violation.status, func.count()).group_by(Violation.status)):
        totals[status] = count

    by_severity = {s: {"open": 0, "accepted": 0} for s in SEVERITIES}
    for severity, status, count in session.execute(
            select(SodRule.severity, Violation.status, func.count())
            .select_from(Violation).join(SodRule, SodRule.id == Violation.rule_id)
            .where(Violation.status.in_(LIVE)).group_by(SodRule.severity, Violation.status)):
        by_severity[severity][status] = count

    controls: Dict[str, Dict[str, Any]] = {}
    for control, status, count, score in session.execute(
            select(SodRule.nist_control, Violation.status, func.count(), func.sum(_weight()))
            .select_from(Violation).join(SodRule, SodRule.id == Violation.rule_id)
            .where(Violation.status.in_(LIVE)).group_by(SodRule.nist_control, Violation.status)):
        entry = controls.setdefault(control, {
            "control": control, "title": NIST_TITLES.get(control, ""), "open": 0, "accepted": 0,
            "score": 0.0})
        entry[status] = count
        entry["score"] += float(score)
    by_control = sorted(controls.values(), key=lambda e: (-e["score"], e["control"]))

    users: List[Dict[str, Any]] = []
    user_rows = session.execute(
        select(User.id, User.username, User.full_name, User.department,
               func.sum(case((Violation.status == "open", 1), else_=0)),
               func.sum(case((Violation.status == "accepted", 1), else_=0)),
               func.sum(_weight()))
        .select_from(Violation).join(SodRule, SodRule.id == Violation.rule_id)
        .join(User, User.id == Violation.user_id)
        .where(Violation.status.in_(LIVE)).group_by(User.id, User.username, User.full_name, User.department))
    for uid, username, full_name, department, open_n, accepted_n, score in user_rows:
        score = float(score)
        users.append({"user_id": uid, "username": username, "full_name": full_name,
                      "department": department, "open": int(open_n), "accepted": int(accepted_n),
                      "score": round(score, 1), "rating": rating(score)})
    users.sort(key=lambda u: (-u["score"], u["username"]))

    return {"generated_at": utcnow().isoformat(timespec="seconds") + "Z", "totals": totals,
            "by_severity": by_severity, "by_control": by_control, "users": users,
            "scoring": {"severity_weights": SEVERITY_WEIGHT, "accepted_factor": ACCEPTED_FACTOR}}


def _safe_cell(value: Any) -> str:
    """Stop spreadsheet formula injection: text starting with = + - @ would run as a formula."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def exceptions_csv(session: Session, include_remediated: bool = False) -> str:
    query = (select(Violation, SodRule, User)
             .join(SodRule, SodRule.id == Violation.rule_id)
             .join(User, User.id == Violation.user_id)
             .order_by(Violation.id))
    if not include_remediated:
        query = query.where(Violation.status.in_(LIVE))
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["violation_id", "username", "department", "rule_code", "rule_name", "risk_rating",
                     "nist_control", "nist_title", "roles_a", "roles_b", "status", "detected_at",
                     "resolution_note"])
    for violation, rule, user in session.execute(query):
        evidence = violation.evidence or {}
        writer.writerow([_safe_cell(x) for x in (
            violation.id, user.username, user.department, rule.code, rule.name, rule.severity.title(),
            rule.nist_control, NIST_TITLES.get(rule.nist_control, ""),
            "; ".join(evidence.get("roles_a", [])), "; ".join(evidence.get("roles_b", [])),
            violation.status, violation.detected_at.isoformat(timespec="seconds"),
            violation.resolution_note)])
    return out.getvalue()
