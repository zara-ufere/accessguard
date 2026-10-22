"""Request and response models (these also generate the interactive API docs)."""
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field
from typing_extensions import Literal

Severity = Literal["low", "medium", "high", "critical"]
CODE = r"^[a-z0-9._-]+$"


class UserIn(BaseModel):
    username: str = Field(min_length=2, max_length=64, pattern=CODE, examples=["carol"])
    full_name: str = Field(min_length=1, max_length=128, examples=["Carol Nguyen"])
    department: str = Field(default="", max_length=64, examples=["Finance"])


class PermissionIn(BaseModel):
    code: str = Field(min_length=2, max_length=64, pattern=CODE, examples=["payments.approve"])
    description: str = Field(default="", max_length=255)


class RoleIn(BaseModel):
    name: str = Field(min_length=2, max_length=64, examples=["AP Approver"])
    description: str = Field(default="", max_length=255)


class RolePermissionIn(BaseModel):
    permission_code: str = Field(min_length=2, max_length=64)


class RuleIn(BaseModel):
    code: str = Field(min_length=2, max_length=32, pattern=r"^[A-Za-z0-9._-]+$", examples=["SOD-001"])
    name: str = Field(min_length=3, max_length=128)
    description: str = Field(default="", max_length=500)
    permission_a: str = Field(min_length=2, max_length=64)
    permission_b: str = Field(min_length=2, max_length=64)
    severity: Severity
    nist_control: str = Field(default="AC-5", pattern=r"^[A-Z]{2}-\d{1,2}$")


class RuleActiveIn(BaseModel):
    active: bool


class AssignIn(BaseModel):
    role_id: int
    justification: Optional[str] = Field(default=None, max_length=500)
    override: bool = False


class PreviewIn(BaseModel):
    role_id: int


class AcceptIn(BaseModel):
    justification: str = Field(min_length=10, max_length=500)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    full_name: str
    department: str
    status: str
    created_at: datetime


class RoleRef(BaseModel):
    id: int
    name: str


class UserDetailOut(UserOut):
    roles: List[RoleRef]
    permissions: List[str]


class PermissionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    code: str
    description: str


class RoleOut(BaseModel):
    id: int
    name: str
    description: str
    permissions: List[str]


class RuleOut(BaseModel):
    id: int
    code: str
    name: str
    description: str
    permission_a: str
    permission_b: str
    severity: str
    nist_control: str
    active: bool


class ConflictOut(BaseModel):
    rule: str
    name: str
    severity: str
    nist_control: str
    roles_a: List[str]
    roles_b: List[str]
    blocking: bool


class PreviewOut(BaseModel):
    allowed: bool
    requires_override: bool
    conflicts: List[ConflictOut]


class AssignOut(BaseModel):
    grant_id: int
    user_id: int
    role_id: int
    new_conflicts: List[ConflictOut]


class ViolationOut(BaseModel):
    id: int
    user_id: int
    username: str
    rule: str
    rule_name: str
    severity: str
    nist_control: str
    status: str
    roles_a: List[str]
    roles_b: List[str]
    detected_at: datetime
    last_seen_at: datetime
    resolved_at: Optional[datetime]
    resolved_by: Optional[str]
    resolution_note: Optional[str]


class ScanOut(BaseModel):
    created: int
    refreshed: int
    closed: int


class AuditOut(BaseModel):
    seq: int
    ts: str
    actor: str
    action: str
    entity_type: str
    entity_id: str
    details: Dict[str, Any]
    prev_hash: str
    hash: str


class VerifyOut(BaseModel):
    ok: bool
    checked: int
    head_seq: int
    head_hash: str
    first_bad_seq: Optional[int] = None
    problem: Optional[str] = None
