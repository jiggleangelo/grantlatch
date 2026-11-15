import re

from .catalogue import SCOPES, classify_scope

SUBJECT_RE = re.compile(r"^sub_[A-Za-z0-9_]{1,64}$")
AGENT_RE = re.compile(r"^agt_[A-Za-z0-9_]{1,64}$")
MAX_SCOPE_LENGTH = 100
MAX_LOOKBACK_DAYS = 3650


def validate_agent_id(agent_id):
    if not isinstance(agent_id, str) or not AGENT_RE.fullmatch(agent_id):
        raise ValueError("agent_id_invalid")


def validate_limits(scopes, limits):
    if not isinstance(limits, dict):
        raise ValueError("limits_invalid")
    allowed = set()
    for scope in scopes:
        allowed.update(SCOPES[scope]["limits"])
    if set(limits) - allowed:
        raise ValueError("limit_unknown")
    clean = {}
    if "bank.transactions:read" in scopes and "max_lookback_days" not in limits:
        raise ValueError("lookback_limit_required")
    for key, value in limits.items():
        if key == "max_lookback_days":
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError("limit_invalid")
            if not 0 <= value <= MAX_LOOKBACK_DAYS:
                raise ValueError("limit_out_of_range")
            clean[key] = value
        else:
            raise ValueError("limit_unknown")
    return clean


def validate_request(subject_ref, scopes, limits, purpose, ttl_seconds):
    if not SUBJECT_RE.fullmatch(subject_ref or ""):
        raise ValueError("subject_ref_invalid")
    if not isinstance(purpose, str) or not purpose.strip() or len(purpose) > 200:
        raise ValueError("purpose_invalid")
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
        raise ValueError("ttl_invalid")
    if not 60 <= ttl_seconds <= 90 * 24 * 3600:
        raise ValueError("ttl_out_of_range")
    if not isinstance(scopes, (tuple, list)) or not scopes:
        raise ValueError("scopes_empty")
    if len(scopes) > 20 or len(set(scopes)) != len(scopes):
        raise ValueError("scopes_invalid")
    for scope in scopes:
        if not isinstance(scope, str) or len(scope) > MAX_SCOPE_LENGTH:
            raise ValueError("scope_invalid")
        code, _ = classify_scope(scope)
        if code:
            raise ValueError(code)
    return validate_limits(scopes, limits)


def validate_action_scope(scope):
    if not isinstance(scope, str) or not scope or len(scope) > MAX_SCOPE_LENGTH:
        return "scope_invalid", "scope is invalid"
    return classify_scope(scope)
