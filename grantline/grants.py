from dataclasses import dataclass, field


@dataclass(frozen=True)
class GrantRequest:
    request_id: str
    agent_id: str
    subject_ref: str
    scopes: tuple[str, ...]
    limits: dict
    purpose: str
    ttl_seconds: int
    created_at: float
    status: str


@dataclass
class Grant:
    grant_id: str
    request_id: str
    agent_id: str
    subject_ref: str
    scopes: tuple[str, ...]
    limits: dict
    purpose: str
    issued_at: float
    expires_at: float
    connection_ref: str
    status: str = "active"
    revoked_at: float | None = None
    revoked_by: str | None = None
    hook_pending: bool = False
    contact_ref: str | None = None


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str
    detail: str
    grant_id: str | None
