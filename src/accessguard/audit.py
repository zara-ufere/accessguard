"""Tamper-evident audit trail.

Each entry stores the hash of the entry before it, and its own hash covers all of
its fields plus that previous hash. Changing, removing or reordering any entry
breaks every hash after it, which `verify` detects.
"""
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import GENESIS_HASH, AuditHead, AuditLog, utcnow


def canonical(value: Any) -> str:
    """Stable JSON: sorted keys, no whitespace, ASCII only."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def compute_hash(prev_hash: str, seq: int, ts: str, actor: str, action: str,
                 entity_type: str, entity_id: str, details: str) -> str:
    payload = canonical([prev_hash, seq, ts, actor, action, entity_type, entity_id, details])
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def record(session: Session, actor: str, action: str, entity_type: str,
           entity_id: Any, details: Optional[Dict[str, Any]] = None) -> AuditLog:
    """Append one entry inside the caller's transaction.

    The head row is locked (SELECT ... FOR UPDATE on PostgreSQL) so concurrent writers
    take turns and the chain never forks. If the caller's transaction rolls back, the
    audit entry rolls back with it.
    """
    head = session.execute(select(AuditHead).where(AuditHead.id == 1).with_for_update()).scalar_one()
    seq = head.last_seq + 1
    ts = utcnow().isoformat(timespec="microseconds") + "Z"
    details_json = canonical(details or {})
    entry_hash = compute_hash(head.last_hash, seq, ts, actor, action, entity_type,
                              str(entity_id), details_json)
    entry = AuditLog(seq=seq, ts=ts, actor=actor, action=action, entity_type=entity_type,
                     entity_id=str(entity_id), details=details_json,
                     prev_hash=head.last_hash, hash=entry_hash)
    session.add(entry)
    head.last_seq = seq
    head.last_hash = entry_hash
    session.flush()
    return entry


@dataclass
class VerifyResult:
    ok: bool
    checked: int
    head_seq: int
    head_hash: str
    first_bad_seq: Optional[int] = None
    problem: Optional[str] = None


def verify(session: Session) -> VerifyResult:
    """Recompute the whole chain and compare it with what is stored."""
    head = session.get(AuditHead, 1)
    prev_hash, expected_seq, checked = GENESIS_HASH, 1, 0
    for row in session.scalars(select(AuditLog).order_by(AuditLog.seq)):
        problem = None
        if row.seq != expected_seq:
            problem = f"expected entry {expected_seq} but found {row.seq} (entry missing or reordered)"
        elif row.prev_hash != prev_hash:
            problem = "previous-hash link does not match the entry before it"
        elif row.hash != compute_hash(row.prev_hash, row.seq, row.ts, row.actor, row.action,
                                      row.entity_type, row.entity_id, row.details):
            problem = "stored hash does not match the entry contents (entry was altered)"
        if problem:
            return VerifyResult(False, checked, head.last_seq, head.last_hash, row.seq, problem)
        prev_hash, expected_seq, checked = row.hash, expected_seq + 1, checked + 1
    if head.last_seq != checked or head.last_hash != prev_hash:
        return VerifyResult(False, checked, head.last_seq, head.last_hash, checked + 1,
                            "audit head does not match the last entry (entries removed from the end)")
    return VerifyResult(True, checked, head.last_seq, head.last_hash)
