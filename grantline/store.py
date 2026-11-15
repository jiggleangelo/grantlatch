import copy
import hashlib
import json
import os
import re
import secrets
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from .policy import AGENT_RE, SUBJECT_RE

SCOPE_RE = re.compile(r'^[a-z0-9_.-]{1,60}:[a-z0-9_-]{1,30}$')
FORBIDDEN_PREFIXES = ('payments.', 'payment.', 'card.', 'cards.', 'money.', 'bank.payments')
MAX_GRANTS = 200
ORDINARY_AUDIT_LIMIT = 4980
CONTROL_AUDIT_LIMIT = 3 * MAX_GRANTS
MAX_AUDIT = ORDINARY_AUDIT_LIMIT + CONTROL_AUDIT_LIMIT
CONTROL_EVENTS = frozenset(('grant.expired', 'grant.revoked', 'revoke_hook.not_delivered'))
CAPACITY_MESSAGE = 'Audit capacity reached. Export and Delete this workspace, then start a new workspace to run more checks. Revocation remains available.'


class StoreError(Exception):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def iso_time(value):
    return datetime.fromtimestamp(float(value), timezone.utc).isoformat().replace('+00:00', 'Z')


def parse_time(value, default):
    if value is None or value == '':
        return float(default)
    if not isinstance(value, str):
        raise StoreError('at must be an ISO-8601 string')
    try:
        parsed = datetime.fromisoformat(value[:-1] + '+00:00' if value.endswith('Z') else value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        stamp = parsed.timestamp()
        iso_time(stamp)
        return stamp
    except (TypeError, ValueError, OverflowError, OSError):
        raise StoreError('at must be a valid, representable ISO-8601 time')


def forbidden(scope):
    return isinstance(scope, str) and scope.startswith(FORBIDDEN_PREFIXES)


def depth(value, level=0):
    if not isinstance(value, (dict, list)):
        return
    if level > 4:
        raise StoreError('JSON nesting must be 4 levels or less')
    for item in value.values() if isinstance(value, dict) else value:
        depth(item, level + 1)


def validate_catalogue(value):
    depth(value)
    if not isinstance(value, dict) or set(value) != {'scopes'} or not isinstance(value['scopes'], dict):
        raise StoreError('field scopes: catalogue must contain one scopes object')
    if len(value['scopes']) > 200:
        raise StoreError('field scopes: at most 200 scopes are allowed')
    clean = {}
    for name, item in value['scopes'].items():
        if not isinstance(name, str) or not SCOPE_RE.fullmatch(name):
            raise StoreError(f'field scopes.{name}: invalid scope name')
        if not isinstance(item, dict):
            raise StoreError(f'field scopes.{name}: must be an object')
        label, limits = item.get('label'), item.get('limits', {})
        if not isinstance(label, str) or not label.strip() or len(label) > 120:
            raise StoreError(f'field scopes.{name}.label: must be 1 to 120 characters')
        if not isinstance(limits, dict) or len(limits) > 5:
            raise StoreError(f'field scopes.{name}.limits: at most 5 limits are allowed')
        checked = {}
        for limit_name, rule in limits.items():
            if not isinstance(limit_name, str) or not re.fullmatch(r'[A-Za-z0-9_]{1,60}', limit_name):
                raise StoreError(f'field scopes.{name}.limits: invalid limit name')
            if not isinstance(rule, dict) or set(rule) != {'type', 'param'}:
                raise StoreError(f'field scopes.{name}.limits.{limit_name}: type and param are required')
            if rule['type'] not in ('max', 'oneof'):
                raise StoreError(f'field scopes.{name}.limits.{limit_name}.type: use max or oneof')
            if not isinstance(rule['param'], str) or not re.fullmatch(r'[A-Za-z0-9_]{1,60}', rule['param']):
                raise StoreError(f'field scopes.{name}.limits.{limit_name}.param: invalid parameter name')
            checked[limit_name] = dict(rule)
        clean[name] = {'label': label.strip(), 'limits': checked, 'forbidden': forbidden(name)}
    return {'scopes': clean}


def verify_chain(events):
    previous = '0' * 64
    for sequence, event in enumerate(events, 1):
        if not isinstance(event, dict):
            return False, sequence
        candidate = dict(event)
        found = candidate.pop('hash', None)
        if candidate.get('seq') != sequence or candidate.get('prev_hash') != previous:
            return False, sequence
        try:
            expected = hashlib.sha256((previous + canonical(candidate)).encode()).hexdigest()
        except (ValueError, TypeError):
            return False, sequence
        if found != expected:
            return False, sequence
        previous = found
    return True, None


def audit_remaining(state, control=False):
    used = sum((event['event'] in CONTROL_EVENTS) == control for event in state['audit'])
    return max(0, (CONTROL_AUDIT_LIMIT if control else ORDINARY_AUDIT_LIMIT) - used)


def require_capacity(state, count=1, control=False):
    if audit_remaining(state, control) < count:
        raise StoreError(CAPACITY_MESSAGE)


def append_event(state, event, actor_type, actor_id, subject_ref=None, grant_id=None, data=None, control=False, now=None):
    if control != (event in CONTROL_EVENTS):
        raise StoreError('invalid audit event budget')
    require_capacity(state, control=control)
    events = state['audit']
    previous = events[-1]['hash'] if events else '0' * 64
    row = {'seq': len(events) + 1, 'ts': float(time.time() if now is None else now),
           'event': str(event)[:64], 'actor_type': str(actor_type)[:16],
           'actor_id': str(actor_id)[:80], 'subject_ref': subject_ref,
           'grant_id': grant_id, 'data': copy.deepcopy(data or {}), 'prev_hash': previous}
    row['hash'] = hashlib.sha256((previous + canonical(row)).encode()).hexdigest()
    events.append(row)
    return row


SAMPLE_CATALOGUE = validate_catalogue({'scopes': {
    'bank.accounts:read': {'label': 'See made-up account names', 'limits': {}},
    'bank.transactions:read': {'label': 'Read made-up transactions', 'limits': {
        'max_lookback_days': {'type': 'max', 'param': 'lookback_days'}}},
    'bank.payments:initiate': {'label': 'Initiate a payment (always forbidden)', 'limits': {}}
}})


class WorkspaceStore:
    def __init__(self, data_dir, clock=time.time, data_cap_mb=200):
        self.root = Path(data_dir)
        self.ws_root = self.root / 'ws'
        self.tomb_root = self.root / 'tombstones'
        self.meta_path = self.root / 'meta.json'
        self.clock = clock
        self.data_cap = int(float(data_cap_mb) * 1024 * 1024)
        # Fixed memory, including for nonexistent workspace tokens.
        self.locks = tuple(threading.RLock() for _ in range(256))
        self.meta_lock = threading.Lock()
        self.storage_lock = threading.RLock()
        self.root.mkdir(parents=True, exist_ok=True)
        self.ws_root.mkdir(exist_ok=True)
        self.tomb_root.mkdir(exist_ok=True)
        self.total_bytes = self._total_bytes()
        if not self.meta_path.exists():
            self._write_json(self.meta_path, {'workspace_creations': []})

    @staticmethod
    def key(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def lock_for(self, key):
        return self.locks[int(key[:8], 16) % len(self.locks)]

    @staticmethod
    def _fsync_directory(directory):
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _total_bytes(self):
        return sum(path.stat().st_size for path in self.root.rglob('*') if path.is_file())

    def _write_bytes(self, path, raw, enforce_cap=True):
        with self.storage_lock:
            old_size = path.stat().st_size if path.exists() else 0
            if enforce_cap and self.total_bytes - old_size + len(raw) > self.data_cap:
                raise StoreError('global_data_capacity_reached: Export and Delete this workspace to free space')
            temporary = path.with_name(path.name + '.tmp-' + secrets.token_hex(6))
            try:
                with open(temporary, 'wb') as output:
                    output.write(raw)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, path)
                self.total_bytes += len(raw) - old_size
                self._fsync_directory(path.parent)
            finally:
                if temporary.exists():
                    temporary.unlink()

    def _write_json(self, path, value):
        self._write_bytes(path, canonical(value).encode())

    def _admit_creation(self, client_ip=None):
        with self.meta_lock:
            meta = json.loads(self.meta_path.read_text())
            now = float(self.clock())
            recent = []
            for entry in meta.get('workspace_creations', []):
                row = entry if isinstance(entry, dict) else {'at': entry, 'ip': None}
                if now - float(row['at']) < 3600:
                    recent.append(row)
            ip_key = self.key(client_ip) if client_ip is not None else None
            if ip_key is not None and sum(row.get('ip') == ip_key for row in recent) >= 10:
                raise StoreError('workspace_creation_ip_rate_reached: try again after one hour')
            if len(recent) >= 60:
                raise StoreError('workspace_creation_rate_reached')
            if sum(item.is_dir() for item in self.ws_root.iterdir()) >= 3000:
                raise StoreError('workspace_capacity_reached')
            recent.append({'at': now, 'ip': ip_key})
            self._write_json(self.meta_path, {'workspace_creations': recent})

    def create(self, sample=False, client_ip=None):
        self._admit_creation(client_ip)
        token = secrets.token_urlsafe(24)
        key = self.key(token)
        with self.lock_for(key):
            directory = self.ws_root / key
            if (self.tomb_root / key).exists():
                raise StoreError('workspace_deleted')
            directory.mkdir()
            self._fsync_directory(self.ws_root)
            now = float(self.clock())
            state = {'version': 1, 'created_at': now, 'last_write': None,
                     'sample': bool(sample), 'catalogue': {'scopes': {}}, 'grants': {},
                     'audit': [], 'last_results': [], 'last_batch_counts': {},
                     'pending_batch': [], 'sample_actions': []}
            if sample:
                state['catalogue'] = copy.deepcopy(SAMPLE_CATALOGUE)
                append_event(state, 'catalogue.updated', 'human', 'sample_user', data={'scope_count': 3}, now=now)
                grant = self.issue_grant(state, 'agt_budget_buddy', 'sub_sample', ['bank.transactions:read'],
                                         {'max_lookback_days': 90}, 'Create a made-up monthly summary', 30 * 86400, now)
                base = {'agent_id': 'agt_budget_buddy', 'grant_id': grant['grant_id'],
                        'scope': 'bank.transactions:read', 'params': {'lookback_days': 30}}
                state['sample_actions'] = [base, dict(base, params={'lookback_days': 120}),
                    dict(base, scope='bank.payments:initiate', params={}), dict(base, agent_id='agt_other'),
                    dict(base, grant_id='gr_missing'), dict(base, scope='bank.accounts:read', params={})]
            try:
                self.save_key(key, state, touch=False)
            except Exception:
                if not (directory / 'state.json').exists():
                    directory.rmdir()
                    self._fsync_directory(self.ws_root)
                raise
        return token

    def load(self, token):
        key = self.key(token)
        with self.lock_for(key):
            path = self.ws_root / key / 'state.json'
            if (self.tomb_root / key).exists() or not path.is_file():
                raise StoreError('workspace_not_found')
            try:
                state = json.loads(path.read_text())
            except (OSError, ValueError):
                raise StoreError('workspace_unavailable')
            if not state.get('sample'):
                state['chain_on_load'] = verify_chain(state.get('audit', []))
            return state

    def save(self, token, state, touch=True):
        self.save_key(self.key(token), state, touch)

    def save_key(self, key, state, touch=True):
        with self.lock_for(key):
            directory = self.ws_root / key
            if (self.tomb_root / key).exists() or not directory.is_dir():
                raise StoreError('workspace_deleted')
            value = copy.deepcopy(state)
            value.pop('chain_on_load', None)
            if touch:
                value['last_write'] = float(self.clock())
            raw = canonical(value).encode()
            if len(raw) > 5 * 1024 * 1024:
                raise StoreError('workspace_size_reached: Export and Delete this workspace to free space')
            self._write_bytes(directory / 'state.json', raw)
            state['last_write'] = value['last_write']

    def _delete_key(self, key):
        with self.lock_for(key), self.storage_lock:
            directory = self.ws_root / key
            # Deletion must work even when the storage budget is exhausted.
            self._write_bytes(self.tomb_root / key, str(float(self.clock())).encode(), enforce_cap=False)
            if directory.is_dir():
                removed = sum(path.stat().st_size for path in directory.rglob('*') if path.is_file())
                shutil.rmtree(directory)
                self.total_bytes -= removed
                self._fsync_directory(self.ws_root)

    def delete(self, token):
        self._delete_key(self.key(token))

    def sweep(self):
        now = float(self.clock())
        for directory in list(self.ws_root.iterdir()):
            if not directory.is_dir():
                continue
            with self.lock_for(directory.name):
                try:
                    state = json.loads((directory / 'state.json').read_text())
                    last = state.get('last_write')
                    age = now - float(last if last is not None else state['created_at'])
                    if age >= (90 * 86400 if last is not None else 86400):
                        self._delete_key(directory.name)
                except (OSError, ValueError, KeyError, TypeError):
                    continue
        for tombstone in list(self.tomb_root.iterdir()):
            with self.lock_for(tombstone.name), self.storage_lock:
                try:
                    if now - float(tombstone.read_text()) >= 30 * 86400:
                        size = tombstone.stat().st_size
                        tombstone.unlink()
                        self.total_bytes -= size
                        self._fsync_directory(self.tomb_root)
                except (OSError, ValueError):
                    pass

    def update_catalogue(self, state, catalogue, now=None):
        checked = validate_catalogue(catalogue)
        require_capacity(state)
        now = float(self.clock() if now is None else now)
        old = state['catalogue']['scopes']
        affected = []
        for gid, grant in state['grants'].items():
            if grant.get('revoked_at') is not None or now >= grant['expires_at']:
                continue
            if any(old.get(scope) != checked['scopes'].get(scope) for scope in grant['scopes']):
                affected.append(gid)
        # Capture legacy consent definitions before the first replacement.
        for grant in state['grants'].values():
            grant.setdefault('scope_definitions', {s: copy.deepcopy(old[s]) for s in grant['scopes'] if s in old})
        state['catalogue'] = checked
        state['catalogue_affected_grants'] = affected
        append_event(state, 'catalogue.updated', 'human', 'workspace_owner',
                     data={'scope_count': len(checked['scopes']), 'affected_active_grants': affected}, now=now)
        return affected

    def issue_grant(self, state, agent_id, subject_ref, scopes, limits, purpose, lifetime, now=None):
        now = float(self.clock() if now is None else now)
        if not isinstance(agent_id, str) or not AGENT_RE.fullmatch(agent_id):
            raise StoreError('agent_id must match agt_[A-Za-z0-9_]{1,64}')
        if not isinstance(subject_ref, str) or not SUBJECT_RE.fullmatch(subject_ref):
            raise StoreError('subject_ref must match sub_[A-Za-z0-9_]{1,64}')
        if not isinstance(purpose, str) or not purpose.strip() or len(purpose) > 200:
            raise StoreError('purpose must contain 1 to 200 characters')
        if type(lifetime) is not int or not 60 <= lifetime <= 90 * 86400:
            raise StoreError('lifetime must be from 1 minute to 90 days')
        if len(state['grants']) >= MAX_GRANTS:
            raise StoreError('grant_capacity_reached')
        if not isinstance(scopes, list) or not scopes or len(scopes) > 200 or any(not isinstance(s, str) for s in scopes) or len(set(scopes)) != len(scopes):
            raise StoreError('select one or more unique scopes')
        catalogue = state['catalogue']['scopes']
        expected = {}
        for scope in scopes:
            if forbidden(scope):
                raise StoreError(f'scope_forbidden: {scope}')
            if scope not in catalogue:
                raise StoreError(f'scope_unknown: {scope}')
            for name, rule in catalogue[scope]['limits'].items():
                if name in expected and expected[name] != rule:
                    raise StoreError(f'limit {name} has conflicting definitions across selected scopes')
                expected[name] = rule
        if not isinstance(limits, dict) or set(limits) != set(expected):
            raise StoreError('limits must provide exactly each selected scope\'s limit names')
        for name, rule in expected.items():
            value = limits[name]
            if rule['type'] == 'max':
                if type(value) is not int or not 0 <= value <= 10 ** 9:
                    raise StoreError(f'limit {name} must be an integer from 0 to 1000000000')
            elif not isinstance(value, list) or len(value) > 20 or any(not isinstance(v, str) or len(v) > 32 for v in value):
                raise StoreError(f'limit {name} must be a list of at most 20 short strings')
        grant_id = 'gr_' + secrets.token_hex(12)
        grant = {'grant_id': grant_id, 'agent_id': agent_id, 'subject_ref': subject_ref,
                 'scopes': list(scopes), 'limits': copy.deepcopy(limits), 'purpose': purpose.strip(),
                 'issued_at': now, 'expires_at': now + lifetime, 'revoked_at': None, 'expired_event': False,
                 'scope_definitions': {s: copy.deepcopy(catalogue[s]) for s in scopes}}
        append_event(state, 'grant.issued', 'human', subject_ref, subject_ref, grant_id,
                     {'scopes': scopes, 'purpose_length': len(purpose), 'system_attribution': 'system'}, now=now)
        state['grants'][grant_id] = grant
        return grant

    def revoke(self, state, grant_id, now=None):
        grant = state['grants'].get(grant_id)
        if not grant:
            raise StoreError('grant_not_found')
        if grant.get('revoked_at') is not None:
            raise StoreError('grant_already_revoked')
        require_capacity(state, 2, control=True)
        now = float(self.clock() if now is None else now)
        payload = {'event': 'grant.revoked', 'grant_id': grant_id, 'agent_id': grant['agent_id'], 'revoked_at': iso_time(now)}
        append_event(state, 'grant.revoked', 'human', grant['subject_ref'], grant['subject_ref'], grant_id, control=True, now=now)
        append_event(state, 'revoke_hook.not_delivered', 'system', 'system', grant['subject_ref'], grant_id,
                     {'hook': 'not_delivered_copy_payload', 'payload': payload}, control=True, now=now)
        grant['revoked_at'] = now
        return payload

    def check(self, state, action, now=None):
        now = float(self.clock() if now is None else now)
        if not isinstance(action, dict):
            raise StoreError('action must be an object')
        agent, grant_id, scope, params = (action.get(k) for k in ('agent_id', 'grant_id', 'scope', 'params'))
        at = parse_time(action.get('at'), now)
        grant = state['grants'].get(grant_id) if isinstance(grant_id, str) else None
        reason, detail = 'ok', 'action is within the active grant'
        if not isinstance(agent, str) or not AGENT_RE.fullmatch(agent):
            reason, detail = 'agent_invalid', 'agent id is invalid'
        elif forbidden(scope):
            reason, detail = 'scope_forbidden', 'payment, card and money scopes are always denied'
        elif not grant:
            reason, detail = 'grant_not_found', 'grant does not exist'
        elif agent != grant['agent_id']:
            reason, detail = 'agent_mismatch', 'agent does not own this grant'
        elif grant.get('revoked_at') is not None and at >= grant['revoked_at']:
            reason, detail = 'grant_revoked', 'action time is on or after revocation'
        elif at >= grant['expires_at']:
            reason, detail = 'grant_expired', 'action time is on or after expiry'
        elif at < grant['issued_at']:
            reason, detail = 'not_yet_valid', 'action time is before grant issuance'
        elif not isinstance(scope, str) or scope not in state['catalogue']['scopes']:
            reason, detail = 'scope_unknown', 'scope is not in the catalogue'
        elif scope not in grant['scopes']:
            reason, detail = 'scope_not_granted', 'scope is not covered by this grant'
        else:
            rules = state['catalogue']['scopes'][scope]['limits']
            original = grant.get('scope_definitions', {}).get(scope, {}).get('limits')
            if any(name not in grant['limits'] for name in rules):
                reason, detail = 'limit_not_in_grant', 'catalogue requires a limit missing from this grant; issue a new grant'
            elif original is not None and original != rules:
                reason, detail = 'grant_catalogue_changed', 'scope rules changed since consent; issue a new grant'
            elif not isinstance(params, dict) or len(params) > 10:
                reason, detail = 'params_invalid', 'params must be an object with at most 10 keys'
            else:
                for name, rule in rules.items():
                    param = rule['param']
                    value, allowed = params.get(param), grant['limits'][name]
                    if rule['type'] == 'max':
                        if type(allowed) is not int:
                            reason, detail = 'limit_not_in_grant', f'{name} has no compatible grant limit'
                        elif type(value) is not int:
                            reason, detail = 'params_invalid', f'{param} must be an integer'
                        elif value > allowed:
                            reason, detail = f'limit_exceeded:{name}', f'{param} exceeds {allowed}'
                    else:
                        if not isinstance(allowed, list):
                            reason, detail = 'limit_not_in_grant', f'{name} has no compatible grant limit'
                        elif not isinstance(value, str):
                            reason, detail = 'params_invalid', f'{param} must be a string'
                        elif value not in allowed:
                            reason, detail = f'value_not_allowed:{name}', f'{param} is not in the allowed list'
                    if reason != 'ok':
                        break
        require_capacity(state)
        expires = grant and now >= grant['expires_at'] and not grant.get('expired_event')
        if expires:
            require_capacity(state, control=True)
        known = set()
        if isinstance(scope, str) and scope in state['catalogue']['scopes']:
            known = {rule['param'] for rule in state['catalogue']['scopes'][scope]['limits'].values()}
        clean = {key: value for key, value in params.items() if key in known} if isinstance(params, dict) else {}
        data = {'scope': scope if isinstance(scope, str) else 'invalid_scope', 'params': clean,
                'dropped_params': len(params) - len(clean) if isinstance(params, dict) else 0,
                'allow': reason == 'ok', 'reason': reason, 'at': iso_time(at)}
        canonical(data)
        if expires:
            append_event(state, 'grant.expired', 'system', 'system', grant['subject_ref'], grant_id, control=True, now=now)
            grant['expired_event'] = True
        append_event(state, 'action.checked', 'agent', agent if isinstance(agent, str) else 'invalid_agent',
                     grant.get('subject_ref') if grant else None, grant_id if grant else None, data, now=now)
        return {'allow': reason == 'ok', 'decision': 'ALLOW' if reason == 'ok' else 'DENY',
                'reason': reason, 'detail': detail, 'agent_id': agent, 'grant_id': grant_id,
                'scope': scope, 'params': copy.deepcopy(params), 'at': iso_time(at), 'line': action.get('_line')}
