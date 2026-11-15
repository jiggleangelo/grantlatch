import copy
import hashlib
import hmac
import json
import secrets
import threading
from contextlib import contextmanager

ALLOWED_PARAMS = {"lookback_days", "account_type"}


class AuditLog:
    """Bounded HMAC chain with a separate budget for lifecycle events.

    Workspace reserves lifecycle capacity from its maximum record counts.
    Agent traffic and manual hook retries cannot consume that reservation.
    The committed head detects in-process truncation, not process compromise.
    """

    def __init__(self, clock, key=None, max_events=1000, control_events=0):
        self.clock = clock
        self._key = key or secrets.token_bytes(32)
        self._max_events = max_events
        self._control_limit = control_events
        self._ordinary_count = 0
        self._control_count = 0
        self._events = []
        self._head_hash = "0" * 64
        self._head_count = 0
        self._lock = threading.RLock()

    @staticmethod
    def _canonical(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    @contextmanager
    def capacity(self, count=1, *, control=False):
        """Hold the append lock while checking capacity and performing work.

        Callers must append at most count events in the selected budget. Holding
        this lock prevents another writer consuming capacity before a side effect.
        """
        with self._lock:
            used = self._control_count if control else self._ordinary_count
            limit = self._control_limit if control else self._max_events
            if used + count > limit:
                raise RuntimeError("audit_capacity_reached")
            yield

    @property
    def remaining(self):
        with self._lock:
            return self._max_events - self._ordinary_count

    def append(self, event, actor_type, actor_id, subject_ref, grant_id=None,
               data=None, *, control=False):
        with self.capacity(control=control):
            data = copy.deepcopy(data or {})
            if "params" in data:
                params = data["params"] if isinstance(data["params"], dict) else {}
                clean = {key: params[key] for key in params if key in ALLOWED_PARAMS}
                dropped = len(params) - len(clean)
                data["params"] = clean
                if dropped:
                    data["dropped_params"] = dropped
            base = {
                "seq": len(self._events) + 1,
                "ts": self.clock(),
                "event": str(event)[:64],
                "actor_type": str(actor_type)[:16],
                "actor_id": str(actor_id)[:80],
                "subject_ref": subject_ref,
                "grant_id": grant_id,
                "data": data,
                "prev_hash": self._head_hash,
            }
            base["hash"] = hmac.new(
                self._key, self._canonical(base).encode(), hashlib.sha256
            ).hexdigest()
            self._events.append(base)
            self._head_hash = base["hash"]
            self._head_count = len(self._events)
            if control:
                self._control_count += 1
            else:
                self._ordinary_count += 1
            return copy.deepcopy(base)

    @property
    def head_hash(self):
        with self._lock:
            return self._head_hash

    @property
    def event_count(self):
        with self._lock:
            return self._head_count

    def events(self, subject_ref=None):
        with self._lock:
            rows = self._events
            if subject_ref is not None:
                rows = [event for event in rows if event["subject_ref"] == subject_ref]
            return copy.deepcopy(rows)

    def verify(self):
        with self._lock:
            previous = "0" * 64
            for seq, event in enumerate(self._events, 1):
                candidate = dict(event)
                found = candidate.pop("hash", None)
                if candidate.get("seq") != seq or candidate.get("prev_hash") != previous:
                    return False, seq
                expected = hmac.new(
                    self._key, self._canonical(candidate).encode(), hashlib.sha256
                ).hexdigest()
                if not hmac.compare_digest(str(found or ""), expected):
                    return False, seq
                previous = found
            if len(self._events) != self._head_count or previous != self._head_hash:
                return False, len(self._events) + 1
            return True, None
