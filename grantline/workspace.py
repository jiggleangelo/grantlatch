import secrets
import threading
import time
from collections import deque
from dataclasses import replace

from .audit import AuditLog
from .catalogue import SCOPES, TARGETS
from .connectors import FakeAggregatorConnector
from .grants import Decision, Grant, GrantRequest
from .policy import validate_action_scope, validate_agent_id, validate_request
from .vault import FakeVault

AGENTS = {
    "agt_budget_buddy": {"name": "Budget Buddy (made-up)", "category": "finance"},
    "agt_trip_planner": {"name": "Trip Planner (made-up)", "category": "travel"},
}


class Workspace:
    def __init__(self, clock=time.time, vault=None, connectors=None, max_requests=100,
                 max_grants=100, max_events=1000, rate_limit=240, rate_window=60):
        self.clock = clock
        self.vault = vault if vault is not None else FakeVault()
        self.connectors = connectors if connectors is not None else {
            "fake_aggregator": FakeAggregatorConnector()
        }
        # Each request can expire once. Each grant needs at most a revocation
        # and its initial hook, or one expiry. Reserve one additional hook retry
        # per grant so a full ordinary log still permits provider recovery.
        self.audit = AuditLog(clock, max_events=max_events,
                              control_events=max_requests + 3 * max_grants)
        self.requests = {}
        self.grants = {}
        self._reserved_retries = set()
        self._max_requests = max_requests
        self._max_grants = max_grants
        self._rate_limit = rate_limit
        self._rate_window = rate_window
        self._operations = {}
        self._lock = threading.RLock()

    def _rate_check(self, agent_id):
        operations = self._operations.setdefault(agent_id, deque())
        now = self.clock()
        while operations and now - operations[0] >= self._rate_window:
            operations.popleft()
        if len(operations) >= self._rate_limit:
            raise RuntimeError("rate_limit_exceeded")
        operations.append(now)

    def _expire_request(self, request):
        if request.status == "pending" and self.clock() >= request.created_at + request.ttl_seconds:
            self.audit.append("grant.request_expired", "system", "system",
                              request.subject_ref, control=True)
            request = replace(request, status="expired")
            self.requests[request.request_id] = request
        return request

    def _pending_request(self, request_id, subject):
        request = self.requests.get(request_id)
        if request is None:
            raise ValueError("request_not_found")
        if subject != request.subject_ref:
            raise ValueError("subject_mismatch")
        request = self._expire_request(request)
        if request.status == "expired":
            raise ValueError("request_expired")
        if request.status != "pending":
            raise ValueError("request_not_pending")
        return request

    def request_grant(self, agent_id, subject_ref, scopes, limits, purpose, ttl_seconds):
        with self._lock:
            validate_agent_id(agent_id)
            if agent_id not in AGENTS:
                raise ValueError("agent_unknown")
            self._rate_check(agent_id)
            clean_limits = validate_request(subject_ref, scopes, limits, purpose, ttl_seconds)
            if len(self.requests) >= self._max_requests:
                raise RuntimeError("request_capacity_reached")
            request = GrantRequest(
                "req_" + secrets.token_hex(8), agent_id, subject_ref, tuple(scopes),
                clean_limits, purpose, ttl_seconds, self.clock(), "pending"
            )
            self.audit.append(
                "grant.requested", "agent", agent_id, subject_ref,
                data={"scopes": list(scopes), "limits": clean_limits,
                      "purpose_length": len(purpose)}
            )
            self.requests[request.request_id] = request
            return request

    def approve(self, request_id, actor_subject_ref, contact=None):
        with self._lock:
            request = self._pending_request(request_id, actor_subject_ref)
            if len(self.grants) >= self._max_grants:
                raise RuntimeError("grant_capacity_reached")
            names = {TARGETS[SCOPES[scope]["target"]]["connector"] for scope in request.scopes}
            if len(names) != 1:
                raise ValueError("connector_mismatch")
            name = next(iter(names))
            connector = self.connectors.get(name)
            if connector is None:
                raise ValueError("connector_unavailable")
            # Check BOTH events before contacting either dependency, while
            # holding the audit lock. No writer can steal these slots.
            with self.audit.capacity(2):
                now = self.clock()
                contact_ref = self.vault.put("revocation_notice", contact) if contact else None
                try:
                    connection = connector.link(request.subject_ref, request.scopes)
                except Exception:
                    if contact_ref:
                        self.vault.delete(contact_ref)
                    raise
                grant = Grant(
                    "gr_" + secrets.token_hex(8), request.request_id, request.agent_id,
                    request.subject_ref, request.scopes, dict(request.limits), request.purpose,
                    now, now + request.ttl_seconds, connection, contact_ref=contact_ref
                )
                self.audit.append("grant.approved", "human", actor_subject_ref,
                                  request.subject_ref, grant.grant_id)
                self.audit.append(
                    "grant.issued", "system", "system", request.subject_ref, grant.grant_id,
                    {"connector": name, "connection_ref": connection}
                )
                self.requests[request_id] = replace(request, status="approved")
                self.grants[grant.grant_id] = grant
                return grant

    def deny(self, request_id, actor_subject_ref):
        with self._lock:
            request = self._pending_request(request_id, actor_subject_ref)
            self.audit.append("grant.denied", "human", actor_subject_ref, request.subject_ref)
            self.requests[request_id] = replace(request, status="denied")

    def _expire(self, grant):
        if grant.status == "active" and self.clock() >= grant.expires_at:
            self.audit.append("grant.expired", "system", "system", grant.subject_ref,
                              grant.grant_id, control=True)
            grant.status = "expired"

    @staticmethod
    def _validate_params(scope, params):
        if not isinstance(params, dict) or len(params) > 10:
            return None, "params_invalid", "parameters are invalid"
        if scope == "bank.transactions:read" and "lookback_days" not in params:
            return None, "params_invalid", "lookback_days required"
        clean = {}
        if "lookback_days" in params:
            value = params["lookback_days"]
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 3650:
                return None, "params_invalid", "lookback_days must be an integer from 0 to 3650"
            clean["lookback_days"] = value
        if "account_type" in params:
            value = params["account_type"]
            if not isinstance(value, str) or len(value) > 32:
                return None, "params_invalid", "account_type is invalid"
            clean["account_type"] = value
        return clean, None, None

    def check(self, agent_id, grant_id, scope, params):
        with self._lock:
            try:
                validate_agent_id(agent_id)
                known_agent = agent_id in AGENTS
            except ValueError:
                known_agent = False
            safe_actor = agent_id if known_agent else "invalid_agent"
            self._rate_check(safe_actor)
            grant = self.grants.get(grant_id) if isinstance(grant_id, str) else None
            if not known_agent:
                decision = Decision(False, "agent_unknown", "agent identity is invalid", grant_id if grant else None)
            elif not grant:
                decision = Decision(False, "grant_not_found", "grant does not exist", None)
            elif agent_id != grant.agent_id:
                decision = Decision(False, "agent_mismatch", "agent does not own this grant", grant_id)
            else:
                self._expire(grant)
                if grant.status == "expired":
                    decision = Decision(False, "grant_expired", "grant expired", grant_id)
                elif grant.status == "revoked":
                    decision = Decision(False, "grant_revoked", "grant revoked", grant_id)
                else:
                    code, detail = validate_action_scope(scope)
                    clean, param_code, param_detail = self._validate_params(scope, params)
                    if code:
                        decision = Decision(False, code, detail, grant_id)
                    elif param_code:
                        decision = Decision(False, param_code, param_detail, grant_id)
                    elif scope not in grant.scopes:
                        decision = Decision(False, "scope_not_granted", "scope is not covered by this grant", grant_id)
                    elif scope == "bank.transactions:read" and clean["lookback_days"] > grant.limits["max_lookback_days"]:
                        limit = grant.limits["max_lookback_days"]
                        decision = Decision(False, "lookback_exceeds_limit", f"lookback exceeds grant limit ({limit})", grant_id)
                    else:
                        decision = Decision(True, "ok", "action is within the active grant", grant_id)
            clean, _, _ = self._validate_params(scope, params)
            audit_params = clean if clean is not None else {}
            dropped = len(params) - len(audit_params) if isinstance(params, dict) else 0
            self.audit.append(
                "action.checked", "agent", safe_actor,
                grant.subject_ref if grant else None, grant_id if grant else None,
                {"scope": scope if isinstance(scope, str) and len(scope) <= 100 else "invalid_scope",
                 "params": audit_params, "dropped_params": dropped,
                 "allow": decision.allow, "reason": decision.reason}
            )
            return decision

    @staticmethod
    def _authorize(grant, actor_type, actor_id, actor_subject_ref):
        if actor_type == "human":
            subject = actor_subject_ref or actor_id
            if subject != grant.subject_ref:
                raise ValueError("subject_mismatch")
            return subject
        if actor_type == "system" and actor_id == "system":
            return "system"
        raise ValueError("actor_invalid")

    def revoke(self, grant_id, actor_type="human", actor_id=None, actor_subject_ref=None):
        with self._lock:
            grant = self.grants.get(grant_id)
            if grant is None:
                raise ValueError("grant_not_found")
            actor = self._authorize(grant, actor_type, actor_id, actor_subject_ref)
            self._expire(grant)
            if grant.status != "active":
                raise ValueError("grant_not_active")
            with self.audit.capacity(2, control=True):
                self.audit.append("grant.revoked", actor_type, actor, grant.subject_ref,
                                  grant_id, control=True)
                grant.status = "revoked"
                grant.revoked_at = self.clock()
                grant.revoked_by = actor_type
                grant.hook_pending = True
                self._call_revoke_hook(grant, control=True)
            return grant

    def _connector_for_grant(self, grant):
        target = SCOPES[grant.scopes[0]]["target"]
        return self.connectors[TARGETS[target]["connector"]]

    def _call_revoke_hook(self, grant, *, control=False):
        with self.audit.capacity(control=control):
            try:
                ok = bool(self._connector_for_grant(grant).revoke(grant.connection_ref))
            except Exception:
                ok = False
            self.audit.append(
                "connector.revoke_hook", "system", "system", grant.subject_ref,
                grant.grant_id, {"outcome": "ok" if ok else "failed"}, control=control
            )
            grant.hook_pending = not ok
            return ok

    def retry_hook(self, grant_id, actor_type="system", actor_id="system", actor_subject_ref=None):
        with self._lock:
            grant = self.grants.get(grant_id)
            if not grant or grant.status != "revoked" or not grant.hook_pending:
                raise ValueError("hook_not_pending")
            self._authorize(grant, actor_type, actor_id, actor_subject_ref)
            # Ordinary retries cannot exhaust other grants' lifecycle slots.
            # One emergency retry per grant remains possible at ordinary capacity.
            emergency = self.audit.remaining == 0 and grant_id not in self._reserved_retries
            self._call_revoke_hook(grant, control=emergency)
            if emergency:
                self._reserved_retries.add(grant_id)
            return grant

    def list_grants(self, subject_ref):
        with self._lock:
            for grant in self.grants.values():
                self._expire(grant)
            return [grant for grant in self.grants.values() if grant.subject_ref == subject_ref]


def seeded_workspace(clock=time.time):
    workspace = Workspace(clock=clock)
    workspace.request_grant(
        "agt_budget_buddy", "sub_demo_user_a", ("bank.transactions:read",),
        {"max_lookback_days": 90}, "Categorize spending for monthly summary", 30 * 86400
    )
    request = workspace.request_grant(
        "agt_budget_buddy", "sub_demo_user_a", ("bank.accounts:read",),
        {}, "Show connected account names and types", 30 * 86400
    )
    workspace.approve(request.request_id, "sub_demo_user_a")
    return workspace
