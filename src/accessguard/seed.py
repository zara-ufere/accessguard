"""Demo organisation with a realistic mix of clean users, open conflicts and an accepted exception."""
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import service, sod
from .models import User, UserRole

PERMISSIONS = {
    "payments.create": "Create payments",
    "payments.approve": "Approve payments",
    "vendors.manage": "Create and edit vendors",
    "code.commit": "Commit application code",
    "prod.deploy": "Deploy to production",
    "prod.db.write": "Write directly to the production database",
    "hr.employee.create": "Create employee records",
    "payroll.run": "Run payroll",
    "audit.log.admin": "Administer or purge audit logs",
    "audit.log.read": "Read audit logs",
    "users.manage": "Create and change user accounts",
    "users.approve_access": "Approve access requests",
}

ROLES = {
    "AP Clerk": ("Accounts payable data entry", ["payments.create"]),
    "AP Approver": ("Approves supplier payments", ["payments.approve"]),
    "Vendor Admin": ("Maintains the vendor master", ["vendors.manage"]),
    "Developer": ("Writes application code", ["code.commit"]),
    "Release Manager": ("Ships releases", ["prod.deploy"]),
    "DBA": ("Database administrator", ["prod.db.write"]),
    "HR Admin": ("Maintains employee records", ["hr.employee.create"]),
    "Payroll Admin": ("Runs payroll", ["payroll.run"]),
    "Security Admin": ("Manages accounts and logging", ["audit.log.admin", "users.manage"]),
    "Access Approver": ("Approves access requests", ["users.approve_access"]),
    "Auditor": ("Reads logs and reports", ["audit.log.read"]),
}

RULES = [
    ("SOD-001", "Create and approve the same payment", "payments.create", "payments.approve", "critical", "AC-5"),
    ("SOD-002", "Maintain vendors and create payments", "vendors.manage", "payments.create", "high", "AC-5"),
    ("SOD-003", "Write code and deploy it to production", "code.commit", "prod.deploy", "high", "AC-5"),
    ("SOD-004", "Write code and change production data directly", "code.commit", "prod.db.write", "medium", "AC-6"),
    ("SOD-005", "Create employees and run payroll", "hr.employee.create", "payroll.run", "high", "AC-5"),
    ("SOD-006", "Change production data and administer its logs", "prod.db.write", "audit.log.admin", "high", "AU-9"),
    ("SOD-007", "Provision accounts and approve the access", "users.manage", "users.approve_access", "medium", "AC-2"),
]

USERS = [
    ("alice", "Alice Moreno", "Finance", ["AP Clerk"]),
    ("bob", "Bob Tran", "Finance", ["AP Approver"]),
    ("heidi", "Heidi Park", "Internal Audit", ["Auditor"]),
    ("ivan", "Ivan Petrov", "IT", ["Access Approver"]),
    ("kofi", "Kofi Mensah", "Engineering", ["Developer"]),
    ("lena", "Lena Fischer", "Engineering", ["Release Manager"]),
]

# Access that already exists when the tool is first pointed at the system.
LEGACY = [
    ("carol", "Carol Nguyen", "Finance", ["AP Clerk", "AP Approver"]),
    ("dave", "Dave Okafor", "Engineering", ["Developer", "Release Manager"]),
    ("erin", "Erin Walsh", "IT", ["DBA", "Security Admin"]),
    ("grace", "Grace Liu", "Engineering", ["Developer", "DBA"]),
    ("mona", "Mona Haddad", "Finance", ["Vendor Admin", "AP Clerk"]),
]


def seed(session: Session, actor: str = "seed") -> bool:
    """Fill an empty database. Returns False (and does nothing) if users already exist."""
    if session.scalar(select(func.count()).select_from(User)):
        return False
    for code, description in PERMISSIONS.items():
        service.create_permission(session, actor, code, description)
    roles = {}
    for name, (description, perms) in ROLES.items():
        role = service.create_role(session, actor, name, description)
        for code in perms:
            service.add_permission_to_role(session, actor, role.id, code)
        roles[name] = role
    for code, name, a, b, severity, control in RULES:
        service.create_rule(session, actor, code, name, a, b, severity, control)

    for username, full_name, department, role_names in USERS:
        user = service.create_user(session, actor, username, full_name, department)
        for role_name in role_names:
            service.assign_role(session, actor, user.id, roles[role_name].id)

    # Legacy access is inserted directly, as if it predated the tool, then found by a scan.
    for username, full_name, department, role_names in LEGACY:
        user = service.create_user(session, actor, username, full_name, department)
        for role_name in role_names:
            session.add(UserRole(user_id=user.id, role_id=roles[role_name].id, granted_by="legacy-import"))
    session.flush()

    # One conflicting grant made through the tool with a documented business reason.
    frank = service.create_user(session, actor, "frank", "Frank Ito", "HR")
    service.assign_role(session, actor, frank.id, roles["HR Admin"].id)
    service.assign_role(session, actor, frank.id, roles["Payroll Admin"].id, override=True,
                        justification="Two-person HR team; CFO reviews every payroll run before release.")

    # A departed employee: their access no longer counts as a conflict.
    judy = service.create_user(session, actor, "judy", "Judy Adeyemi", "HR")
    for role_name in ("HR Admin", "Payroll Admin"):
        session.add(UserRole(user_id=judy.id, role_id=roles[role_name].id, granted_by="legacy-import"))
    session.flush()
    service.disable_user(session, actor, judy.id)

    sod.scan(session, actor)
    session.commit()
    return True
