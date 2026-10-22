"""HTTP API. Read endpoints accept any valid token; changes need an admin token."""
import json
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from . import __version__, audit, reports, service, sod
from .config import Actor, database_url, load_tokens
from .db import init_db, make_engine
from .models import (AuditLog, Permission, Role, RolePermission, SodRule, User, UserRole, Violation)
from .schemas import (AcceptIn, AssignIn, AssignOut, AuditOut, ConflictOut, PermissionIn, PermissionOut,
                      PreviewIn, PreviewOut, RoleIn, RoleOut, RolePermissionIn, RuleActiveIn, RuleIn,
                      RuleOut, ScanOut, UserDetailOut, UserIn, UserOut, VerifyOut, ViolationOut)
from .security import make_auth

STATIC = Path(__file__).parent / "static"


def _conflict_out(c: sod.Conflict) -> ConflictOut:
    return ConflictOut(rule=c.rule_code, name=c.rule_name, severity=c.severity,
                       nist_control=c.nist_control, roles_a=list(c.roles_a),
                       roles_b=list(c.roles_b), blocking=c.blocking)


def _role_out(role: Role) -> RoleOut:
    return RoleOut(id=role.id, name=role.name, description=role.description,
                   permissions=[p.code for p in role.permissions])


def _rule_out(rule: SodRule) -> RuleOut:
    return RuleOut(id=rule.id, code=rule.code, name=rule.name, description=rule.description,
                   permission_a=rule.permission_a.code, permission_b=rule.permission_b.code,
                   severity=rule.severity, nist_control=rule.nist_control, active=rule.active)


def _violation_out(v: Violation) -> ViolationOut:
    evidence = v.evidence or {}
    return ViolationOut(
        id=v.id, user_id=v.user_id, username=v.user.username, rule=v.rule.code, rule_name=v.rule.name,
        severity=v.rule.severity, nist_control=v.rule.nist_control, status=v.status,
        roles_a=evidence.get("roles_a", []), roles_b=evidence.get("roles_b", []),
        detected_at=v.detected_at, last_seen_at=v.last_seen_at, resolved_at=v.resolved_at,
        resolved_by=v.resolved_by, resolution_note=v.resolution_note)


def create_app(engine=None, tokens=None) -> FastAPI:
    engine = engine or make_engine(database_url())
    init_db(engine)
    tokens = load_tokens() if tokens is None else tokens
    reader, admin = make_auth(tokens)

    app = FastAPI(
        title="AccessGuard", version=__version__,
        description="Role-based access, separation of duties detection and a tamper-evident audit trail.")
    app.state.engine = engine
    app.state.sessions = sessionmaker(engine, expire_on_commit=False)

    def get_db(request: Request):
        with request.app.state.sessions() as session:
            yield session

    @app.exception_handler(service.DomainError)
    async def _domain_error(_request, exc: service.DomainError):
        body = {"detail": exc.message}
        if exc.details:
            body["conflicts"] = exc.details
        return JSONResponse(status_code=exc.status_code, content=body)

    @app.exception_handler(IntegrityError)
    async def _integrity_error(_request, _exc):
        return JSONResponse(status_code=409, content={"detail": "The change conflicts with existing data"})

    # ---- meta ------------------------------------------------------------------------
    @app.get("/health", tags=["meta"])
    def health():
        return {"status": "ok", "version": __version__}

    @app.get("/", include_in_schema=False)
    def dashboard():
        return FileResponse(STATIC / "index.html")

    # ---- catalog ---------------------------------------------------------------------
    @app.post("/permissions", response_model=PermissionOut, status_code=201, tags=["catalog"])
    def add_permission(body: PermissionIn, actor: Actor = Depends(admin), db: Session = Depends(get_db)):
        permission = service.create_permission(db, actor.name, body.code, body.description)
        db.commit()
        return permission

    @app.get("/permissions", response_model=List[PermissionOut], tags=["catalog"])
    def list_permissions(_: Actor = Depends(reader), db: Session = Depends(get_db)):
        return db.scalars(select(Permission).order_by(Permission.code)).all()

    @app.post("/roles", response_model=RoleOut, status_code=201, tags=["catalog"])
    def add_role(body: RoleIn, actor: Actor = Depends(admin), db: Session = Depends(get_db)):
        role = service.create_role(db, actor.name, body.name, body.description)
        db.commit()
        return _role_out(role)

    @app.get("/roles", response_model=List[RoleOut], tags=["catalog"])
    def list_roles(_: Actor = Depends(reader), db: Session = Depends(get_db)):
        return [_role_out(r) for r in db.scalars(select(Role).order_by(Role.name))]

    @app.post("/roles/{role_id}/permissions", response_model=RoleOut, status_code=201, tags=["catalog"])
    def grant_permission(role_id: int, body: RolePermissionIn, actor: Actor = Depends(admin),
                         db: Session = Depends(get_db)):
        role = service.add_permission_to_role(db, actor.name, role_id, body.permission_code)
        db.commit()
        return _role_out(role)

    @app.post("/sod-rules", response_model=RuleOut, status_code=201, tags=["rules"])
    def add_rule(body: RuleIn, actor: Actor = Depends(admin), db: Session = Depends(get_db)):
        rule = service.create_rule(db, actor.name, body.code, body.name, body.permission_a,
                                   body.permission_b, body.severity, body.nist_control, body.description)
        db.commit()
        return _rule_out(rule)

    @app.get("/sod-rules", response_model=List[RuleOut], tags=["rules"])
    def list_rules(_: Actor = Depends(reader), db: Session = Depends(get_db)):
        return [_rule_out(r) for r in db.scalars(select(SodRule).order_by(SodRule.code))]

    @app.post("/sod-rules/{rule_id}/active", response_model=RuleOut, tags=["rules"])
    def toggle_rule(rule_id: int, body: RuleActiveIn, actor: Actor = Depends(admin),
                    db: Session = Depends(get_db)):
        rule = service.set_rule_active(db, actor.name, rule_id, body.active)
        db.commit()
        return _rule_out(rule)

    # ---- users and access ------------------------------------------------------------
    @app.post("/users", response_model=UserOut, status_code=201, tags=["users"])
    def add_user(body: UserIn, actor: Actor = Depends(admin), db: Session = Depends(get_db)):
        user = service.create_user(db, actor.name, body.username, body.full_name, body.department)
        db.commit()
        return user

    @app.get("/users", response_model=List[UserOut], tags=["users"])
    def list_users(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                   _: Actor = Depends(reader), db: Session = Depends(get_db)):
        return db.scalars(select(User).order_by(User.username).limit(limit).offset(offset)).all()

    @app.get("/users/{user_id}", response_model=UserDetailOut, tags=["users"])
    def get_user(user_id: int, _: Actor = Depends(reader), db: Session = Depends(get_db)):
        user = service.get_user(db, user_id)
        roles = db.execute(select(Role.id, Role.name).join(UserRole, UserRole.role_id == Role.id)
                           .where(UserRole.user_id == user_id, UserRole.revoked_at.is_(None))
                           .order_by(Role.name)).all()
        permissions = db.scalars(
            select(Permission.code).distinct()
            .join(RolePermission, RolePermission.permission_id == Permission.id)
            .join(UserRole, UserRole.role_id == RolePermission.role_id)
            .where(UserRole.user_id == user_id, UserRole.revoked_at.is_(None))
            .order_by(Permission.code)).all()
        return UserDetailOut(**UserOut.model_validate(user).model_dump(),
                             roles=[{"id": r.id, "name": r.name} for r in roles],
                             permissions=list(permissions))

    @app.post("/users/{user_id}/disable", response_model=UserOut, tags=["users"])
    def disable(user_id: int, actor: Actor = Depends(admin), db: Session = Depends(get_db)):
        user = service.disable_user(db, actor.name, user_id)
        db.commit()
        return user

    @app.post("/users/{user_id}/roles/preview", response_model=PreviewOut, tags=["access"])
    def preview(user_id: int, body: PreviewIn, _: Actor = Depends(reader), db: Session = Depends(get_db)):
        conflicts = service.preview_assignment(db, user_id, body.role_id)
        blocking = any(c.blocking for c in conflicts)
        return PreviewOut(allowed=not blocking, requires_override=blocking,
                          conflicts=[_conflict_out(c) for c in conflicts])

    @app.post("/users/{user_id}/roles", response_model=AssignOut, status_code=201, tags=["access"])
    def assign(user_id: int, body: AssignIn, actor: Actor = Depends(admin), db: Session = Depends(get_db)):
        grant, conflicts = service.assign_role(db, actor.name, user_id, body.role_id,
                                               body.justification, body.override)
        db.commit()
        return AssignOut(grant_id=grant.id, user_id=user_id, role_id=body.role_id,
                         new_conflicts=[_conflict_out(c) for c in conflicts])

    @app.delete("/users/{user_id}/roles/{role_id}", status_code=204, tags=["access"])
    def revoke(user_id: int, role_id: int, reason: Optional[str] = Query(None, max_length=255),
               actor: Actor = Depends(admin), db: Session = Depends(get_db)):
        service.revoke_role(db, actor.name, user_id, role_id, reason)
        db.commit()
        return Response(status_code=204)

    # ---- violations and scans --------------------------------------------------------
    @app.post("/scans", response_model=ScanOut, tags=["violations"])
    def run_scan(actor: Actor = Depends(admin), db: Session = Depends(get_db)):
        result = sod.scan(db, actor.name)
        db.commit()
        return ScanOut(created=result.created, refreshed=result.refreshed, closed=result.closed)

    @app.get("/violations", response_model=List[ViolationOut], tags=["violations"])
    def list_violations(status: Optional[str] = Query(None, pattern="^(open|accepted|remediated)$"),
                        severity: Optional[str] = Query(None, pattern="^(low|medium|high|critical)$"),
                        user_id: Optional[int] = None, limit: int = Query(200, ge=1, le=1000),
                        offset: int = Query(0, ge=0), _: Actor = Depends(reader),
                        db: Session = Depends(get_db)):
        query = select(Violation).join(SodRule, SodRule.id == Violation.rule_id)
        if status:
            query = query.where(Violation.status == status)
        if severity:
            query = query.where(SodRule.severity == severity)
        if user_id:
            query = query.where(Violation.user_id == user_id)
        query = query.order_by(Violation.id).limit(limit).offset(offset)
        return [_violation_out(v) for v in db.scalars(query)]

    @app.post("/violations/{violation_id}/accept", response_model=ViolationOut, tags=["violations"])
    def accept(violation_id: int, body: AcceptIn, actor: Actor = Depends(admin),
               db: Session = Depends(get_db)):
        violation = service.accept_violation(db, actor.name, violation_id, body.justification)
        db.commit()
        return _violation_out(violation)

    # ---- reports and audit -----------------------------------------------------------
    @app.get("/reports/risk", tags=["reports"])
    def risk(_: Actor = Depends(reader), db: Session = Depends(get_db)):
        return reports.risk_report(db)

    @app.get("/reports/exceptions.csv", tags=["reports"])
    def exceptions(include_remediated: bool = False, _: Actor = Depends(reader),
                   db: Session = Depends(get_db)):
        return Response(reports.exceptions_csv(db, include_remediated), media_type="text/csv",
                        headers={"Content-Disposition": 'attachment; filename="exceptions.csv"'})

    @app.get("/audit", response_model=List[AuditOut], tags=["audit"])
    def audit_entries(limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
                      _: Actor = Depends(reader), db: Session = Depends(get_db)):
        rows = db.scalars(select(AuditLog).order_by(AuditLog.seq.desc()).limit(limit).offset(offset))
        return [AuditOut(seq=r.seq, ts=r.ts, actor=r.actor, action=r.action, entity_type=r.entity_type,
                         entity_id=r.entity_id, details=json.loads(r.details), prev_hash=r.prev_hash,
                         hash=r.hash) for r in rows]

    @app.get("/audit/verify", response_model=VerifyOut, tags=["audit"])
    def audit_verify(_: Actor = Depends(reader), db: Session = Depends(get_db)):
        result = audit.verify(db)
        return VerifyOut(**result.__dict__)

    return app


def app_factory() -> FastAPI:
    """Entry point for `uvicorn accessguard.api:app_factory --factory`."""
    return create_app()
