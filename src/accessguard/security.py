"""Bearer-token authentication with two roles: admin (read and write) and auditor (read only)."""
import hmac
from typing import Dict, Optional

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import Actor

_bearer = HTTPBearer(auto_error=False)


def make_auth(tokens: Dict[str, Actor]):
    def reader(credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer)) -> Actor:
        if credentials is None:
            raise HTTPException(401, "Missing bearer token", headers={"WWW-Authenticate": "Bearer"})
        match = None
        for token, actor in tokens.items():  # compare against all, in constant time per token
            if hmac.compare_digest(token.encode(), credentials.credentials.encode()):
                match = actor
        if match is None:
            raise HTTPException(401, "Invalid token", headers={"WWW-Authenticate": "Bearer"})
        return match

    def admin(actor: Actor = Depends(reader)) -> Actor:
        if actor.role != "admin":
            raise HTTPException(403, "This action needs an admin token")
        return actor

    return reader, admin
