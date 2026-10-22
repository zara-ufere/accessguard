# AccessGuard

![CI](https://github.com/zara-ufere/accessguard/actions/workflows/ci.yml/badge.svg)

AccessGuard is an access governance service. It records who holds which roles, finds people whose combined access breaks a separation of duties rule, refuses risky grants before they happen, and keeps a tamper-evident log of every change.

A classic audit finding is one person who can both create and approve the same payment. Spreadsheet reviews catch this months late. AccessGuard checks it at the moment access is granted, keeps checking as roles change, and reports what remains as risk-rated exceptions mapped to NIST SP 800-53 controls.

It is built on FastAPI and SQLAlchemy and runs on SQLite for development or PostgreSQL for real use. The test suite runs against both.

## Quick start

Requires Python 3.9 or newer.

```
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
pytest

export ACCESSGUARD_TOKENS="admin-token-demo:alice:admin,audit-token-demo:bob:auditor"
accessguard seed
accessguard serve
```

Open http://127.0.0.1:8000 and paste `admin-token-demo` to see the dashboard. Interactive API docs are at `/docs`. Tokens look like `token:name:role`, where the role is `admin` (can change data) or `auditor` (read only). The name is what gets written to the audit log. Use your own long random tokens anywhere real.

## What it looks like

![Dashboard](docs/images/dashboard.png)

The dashboard opens on a plain-language summary and a list of findings, most serious first. Other tabs show risk by person, risk by NIST control, and the activity log with its integrity check.

The demo organisation has clean users, open conflicts, and one accepted exception. This is a refused grant, with Kofi already holding the Developer role:

```
POST /users/5/roles   {"role_id": 5}      (Release Manager)

409 Conflict
{
  "detail": "This grant would create a separation of duties conflict that needs an override",
  "conflicts": [{
    "rule": "SOD-003", "name": "Write code and deploy it to production",
    "severity": "high", "nist_control": "AC-5",
    "roles_a": ["Developer"], "roles_b": ["Release Manager"]
  }]
}
```

An admin can still grant it by sending `"override": true` with a written justification of at least ten characters. The conflict is then recorded as an accepted risk, with the reason, who approved it, and an audit entry.

## How it works

**Detection is one SQL query.** A CTE lists each user's effective permissions through their active role grants. It is joined to itself once per side of each rule, so a user matches when they hold both permissions, whether through one role or several.

```sql
WITH effective AS (
  SELECT ur.user_id, ur.role_id, rp.permission_id
  FROM user_roles ur JOIN role_permissions rp ON rp.role_id = ur.role_id
  WHERE ur.revoked_at IS NULL
)
SELECT r.id, a.user_id, a.role_id, b.role_id
FROM sod_rules r
JOIN effective a ON a.permission_id = r.permission_a_id
JOIN effective b ON b.user_id = a.user_id AND b.permission_id = r.permission_b_id
JOIN users u ON u.id = a.user_id
WHERE r.active AND u.status = 'active';
```

**Previews cannot disagree with reality.** To preview a grant, the service adds it inside a SAVEPOINT, runs the same detection query, and rolls the savepoint back. There is no second copy of the rule logic to drift.

**Violations have a lifecycle.** A scan opens a violation for each new conflict, refreshes ones that still exist, and closes ones that no longer do. Scans are idempotent. A partial unique index guarantees at most one live violation per user and rule, while closed ones are kept as history. Creating a rule or growing a role triggers the same reconciliation, so the data stays current without waiting for a scheduled scan.

**The audit log is tamper-evident.** Each entry stores the hash of the entry before it, and its own hash covers every field plus that link. `GET /audit/verify` recomputes the chain and reports the first entry that was altered, removed, or reordered, and also catches entries removed from the end by comparing against a locked head row. Database triggers reject `UPDATE` and `DELETE` on the log table, and every audit write happens in the same transaction as the change it describes, so they commit or roll back together. On PostgreSQL the head row is locked with `SELECT ... FOR UPDATE` so concurrent writers cannot fork the chain.

**Risk scoring is explicit.** Open violations score 10 (critical), 5 (high), 2 (medium) or 1 (low). Accepted risks count at half weight, since they are still real. A user's total maps to None, Low, Medium, High or Critical.

## NIST SP 800-53 mapping

Each rule carries a control ID, and reports roll up by control.

| Control | Title | Used for |
| --- | --- | --- |
| AC-5 | Separation of Duties | Create and approve, vendor and payment, code and deploy, HR and payroll |
| AC-6 | Least Privilege | Developers with direct production data access |
| AC-2 | Account Management | Provisioning accounts and approving the same access |
| AU-9 | Protection of Audit Information | Changing production data and administering its logs |

The mapping is a starting point for an assessor to review, not a compliance claim.

## API overview

| Area | Endpoints |
| --- | --- |
| Catalog | `POST/GET /permissions`, `POST/GET /roles`, `POST /roles/{id}/permissions` |
| Rules | `POST/GET /sod-rules`, `POST /sod-rules/{id}/active` |
| Users and access | `POST/GET /users`, `GET /users/{id}`, `POST /users/{id}/roles/preview`, `POST /users/{id}/roles`, `DELETE /users/{id}/roles/{role_id}`, `POST /users/{id}/disable` |
| Violations | `POST /scans`, `GET /violations`, `POST /violations/{id}/accept` |
| Reports | `GET /reports/risk`, `GET /reports/exceptions.csv` |
| Audit | `GET /audit`, `GET /audit/verify` |

Reads accept any valid token. Everything that changes data needs an admin token. The CSV export neutralises spreadsheet formulas, so a department name like `=HYPERLINK(...)` cannot execute when an auditor opens the file.

## Data model

Full diagram and the reasoning behind each constraint are in [docs/schema.md](docs/schema.md). In short: unique and check constraints, foreign keys, partial unique indexes, a canonical ordering on rule pairs, and append-only triggers on the audit table are all enforced by the database, so no code path can bypass them.

## PostgreSQL and Docker

```
pip install -e ".[dev,postgres]"
export DATABASE_URL="postgresql+psycopg://user:password@localhost:5432/accessguard"
accessguard init-db
```

To run the app and a PostgreSQL database together:

```
docker compose up --build
```

The compose file starts PostgreSQL 16, loads the demo data, and serves on port 8000 with the demo tokens above. Replace the tokens before using it for anything other than a demo.

## Tests

```
pytest                                   # SQLite, in memory
TEST_DATABASE_URL="postgresql+psycopg://user:password@localhost:5432/test" pytest
```

The suite has over 100 tests covering database constraints, detection edge cases (overlapping roles, revoked grants, disabled users, inactive rules), the violation lifecycle, blocked and overridden grants, authentication, report arithmetic, CSV safety, and audit tampering. Tampering tests alter and delete entries directly in the database and confirm verification fails at the right entry. A concurrency test runs eight parallel writers against PostgreSQL and checks that the chain stays valid. Continuous integration runs everything on Python 3.9 and 3.12 with SQLite, and on PostgreSQL 16.

## Limitations and next steps

- Authentication is static bearer tokens. A production deployment would use single sign-on and per-person identities.
- The hash chain proves the log was changed, but someone with full database write access could rebuild the whole chain. Publishing the head hash from `/audit/verify` to a separate system on a schedule closes that gap.
- Rules compare two permissions. Rules over three or more, or over amounts and thresholds, are not modeled.
- Access is permanent until revoked. Time-limited grants and periodic recertification campaigns would be natural additions.
- Single organisation only, and no schema migration tooling yet.

## License

MIT
