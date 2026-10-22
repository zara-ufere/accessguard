"""Runtime configuration read from environment variables."""
import os
from dataclasses import dataclass
from typing import Dict

ROLES = ("admin", "auditor")


@dataclass(frozen=True)
class Actor:
    """Who is making a request. Admins can change data; auditors can only read."""
    name: str
    role: str


def database_url() -> str:
    return os.environ.get("DATABASE_URL", "sqlite:///accessguard.db")


def load_tokens(raw: str = None) -> Dict[str, Actor]:
    """Parse ACCESSGUARD_TOKENS, e.g. 'tok1:alice:admin,tok2:bob:auditor'."""
    if raw is None:
        raw = os.environ.get("ACCESSGUARD_TOKENS", "")
    tokens = {}
    for item in (part.strip() for part in raw.split(",")):
        if not item:
            continue
        try:
            token, name, role = item.split(":")
        except ValueError:
            raise ValueError("ACCESSGUARD_TOKENS entries must look like token:name:role")
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}, got '{role}'")
        if len(token) < 8:
            raise ValueError("tokens must be at least 8 characters")
        tokens[token] = Actor(name=name, role=role)
    return tokens
