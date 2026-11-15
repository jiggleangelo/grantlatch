import copy
import csv
import io
import json
import socket
import tempfile
import threading
import unittest
from contextlib import contextmanager
from email.message import Message
from types import SimpleNamespace
from unittest.mock import patch

import app
from grantline.store import (CAPACITY_MESSAGE, MAX_GRANTS, ORDINARY_AUDIT_LIMIT,
    StoreError, WorkspaceStore, append_event, audit_remaining, parse_time, verify_chain)


CATALOGUE = {'scopes': {'crm.contacts:read': {'label': 'Read contacts', 'limits': {
    'max_records': {'type': 'max', 'param': 'records'},
    'allowed_region': {'type': 'oneof', 'param': 'region'}}}}}


class ReviewFixTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = [1000.0]
        self.store = WorkspaceStore(self.temp.name, clock=lambda: self.now[0])
        self.token = self.store.create()
        self.state = self.store.load(self.token)
        self.store.update_catalogue(self.state, CATALOGUE)
        self.grant = self.store.issue_grant(self.state, 'agt_reader', 'sub_demo', ['crm.contacts:read'],
            {'max_records': 50, 'allowed_region': ['us', 'ca']}, 'Read a summary', 60)
        self.action = {'agent_id': 'agt_reader', 'grant_id': self.grant['grant_id'],
                       'scope': 'crm.contacts:read', 'params': {'records': 20, 'region': 'us'}}
        self.store.save(self.token, self.state)
        self.handler = object.__new__(app.Handler)
        self.handler.server = SimpleNamespace(store=self.store, public_base_url='http://localhost',
            monotonic=lambda: 0, batch_seconds=4)
        self.handler.path = '/w/' + self.token
        self.pages = []
        self.handler.page = lambda title, content, *args, **kwargs: self.pages.append((title, content, kwargs))
        self.handler.redirect = lambda path: None

    def test_random_tokens_do_not_grow_lock_storage(self):
        locks = self.store.locks
        for index in range(10000):
            token = 'missing_' + str(index)
            key = self.store.key(token)
            with self.store.lock_for(key):
                with self.assertRaisesRegex(StoreError, 'workspace_not_found'):
                    self.store.load(token)
        self.assertIs(self.store.locks, locks)
        self.assertEqual(len(locks), 256)

    def test_catalogue_new_limit_denies_and_warns_without_losing_batch(self):
        changed = copy.deepcopy(CATALOGUE)
        changed['scopes']['crm.contacts:read']['limits']['max_pages'] = {'type': 'max', 'param': 'pages'}
        affected = self.store.update_catalogue(self.state, changed)
        self.assertEqual(affected, [self.grant['grant_id']])
        self.handler.run_batch(self.token, self.state, {'batch': [json.dumps(self.action)], 'format': ['jsonl']})
        self.assertEqual(self.state['last_results'][0]['reason'], 'limit_not_in_grant')
        self.assertTrue(verify_chain(self.state['audit'])[0])
        self.handler.catalogue_page(self.token, self.state)
        self.assertIn('affected active grants', self.pages[-1][1])
        self.assertIn(self.grant['grant_id'], self.pages[-1][1])

    def test_changed_or_removed_rules_cannot_silently_broaden_consent(self):
        for replacement in ({}, {'max_records': {'type': 'oneof', 'param': 'records'}}):
            state = copy.deepcopy(self.state)
            changed = copy.deepcopy(CATALOGUE)
            changed['scopes']['crm.contacts:read']['limits'] = replacement
            self.store.update_catalogue(state, changed)
            self.assertEqual(self.store.check(state, self.action)['reason'], 'grant_catalogue_changed')

    def test_full_audit_explains_export_delete_and_hides_continue(self):
        for _ in range(ORDINARY_AUDIT_LIMIT - 2 - len(self.state['audit'])):
            append_event(self.state, 'test.fill', 'system', 'system')
        batch = '\n'.join(json.dumps(self.action) for _ in range(3))
        self.handler.run_batch(self.token, self.state, {'batch': [batch]})
        self.assertEqual(len(self.state['last_results']), 1)
        self.assertEqual(len(self.state['pending_batch']), 2)
        self.assertEqual(audit_remaining(self.state), 0)
        self.assertIn(CAPACITY_MESSAGE, self.pages[-1][1])
        self.assertNotIn('<button>Continue</button>', self.pages[-1][1])
        before = copy.deepcopy(self.state)
        self.handler.run_batch(self.token, self.state, {'continue': ['1']})
        self.assertEqual(before, self.state)
        self.handler.batch_page(self.token, self.store.load(self.token))
        self.assertIn('Export and Delete', self.pages[-1][1])

    def test_all_grants_can_expire_and_revoke_with_full_ordinary_budget(self):
        for _ in range(MAX_GRANTS - 1):
            self.store.issue_grant(self.state, 'agt_reader', 'sub_demo', ['crm.contacts:read'],
                {'max_records': 50, 'allowed_region': ['us']}, 'Read', 60)
        # Exercise all expiry events through real checks before filling ordinary slots.
        self.now[0] += 61
        for grant in self.state['grants'].values():
            result = self.store.check(self.state, dict(self.action, grant_id=grant['grant_id']))
            self.assertEqual(result['reason'], 'grant_expired')
        while audit_remaining(self.state):
            append_event(self.state, 'test.fill', 'system', 'system')
        for gid in self.state['grants']:
            self.store.revoke(self.state, gid)
        self.assertEqual(audit_remaining(self.state, True), 0)
        self.store.save(self.token, self.state)
        loaded = self.store.load(self.token)
        self.assertTrue(all(g['revoked_at'] is not None for g in loaded['grants'].values()))
        self.assertTrue(verify_chain(loaded['audit'])[0])

    def test_invalid_batch_rows_report_physical_line_without_mutating_saved_results(self):
        baseline = self.store.load(self.token)
        for at in ('not a time', 17, '0001-01-01T00:00:00+23:59'):
            text = json.dumps(self.action) + '\n' + json.dumps(dict(self.action, at=at))
            with self.subTest(at=at), self.assertRaisesRegex(StoreError, 'line 2:'):
                self.handler.run_batch(self.token, self.state, {'batch': [text]})
            self.assertEqual(self.store.load(self.token), baseline)
        huge = '{"params":{"records":' + '9' * 5000 + '}}'
        with self.assertRaisesRegex(StoreError, 'line 2:'):
            self.handler.parse_batch('{}\n' + huge, '', 'jsonl')
        # Year 1 itself is valid on platforms that can round-trip it.
        try:
            stamp = parse_time('0001-01-01T00:00:00Z', 0)
        except StoreError:
            pass
        else:
            self.assertTrue(app.iso_time(stamp).startswith('0001-01-01'))

    def test_bom_jsonl_csv_and_non_utf8_upload_errors(self):
        parsed = self.handler.parse_batch('\ufeff' + json.dumps(self.action), '', 'jsonl')
        self.assertEqual(parsed[0]['_line'], 1)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['agent_id', 'grant_id', 'scope', 'params'])
        writer.writerow(['agt_reader', self.grant['grant_id'], 'crm.contacts:read', '{}'])
        parsed = self.handler.parse_batch('\ufeff' + output.getvalue(), 'actions.csv', '')
        self.assertEqual(parsed[0]['_line'], 2)
        self.set_upload(b'\xff')
        with self.assertRaisesRegex(StoreError, 'UTF-8'):
            self.handler.form()
        self.set_upload(b'\xef\xbb\xbf{}')
        self.assertEqual(self.handler.form()['file'], ['{}'])

    def test_results_identify_source_lines_and_preserve_params_across_continue(self):
        text = '\n' + json.dumps(self.action) + '\n\n' + json.dumps(self.action)
        ticks = iter([0, 0, 5])
        self.handler.server.monotonic = lambda: next(ticks)
        self.handler.run_batch(self.token, self.state, {'batch': [text]})
        self.assertEqual(len(self.state['pending_batch']), 1)
        self.handler.server.monotonic = lambda: 0
        self.handler.run_batch(self.token, self.state, {'continue': ['1']})
        self.assertEqual([r['line'] for r in self.state['last_results']], [2, 4])
        body = self.pages[-1][1]
        for field in ('line', 'agent_id', 'grant_id', 'params'):
            self.assertIn('<th>' + field + '</th>', body)
        self.assertEqual(self.state['last_results'][0]['params'], self.action['params'])
        data = []
        self.handler.send_data = lambda status, body, *a, **kw: data.append(body)
        self.handler.results_csv(self.state)
        rows = list(csv.DictReader(io.StringIO(data[0])))
        self.assertEqual([row['line'] for row in rows], ['2', '4'])
        self.assertEqual(json.loads(rows[0]['params']), self.action['params'])

    def test_csv_formula_injection_is_escaped_in_every_text_column(self):
        state = {'last_results': [{'line': 1, 'decision': 'DENY', 'agent_id': '=1+1',
            'grant_id': '+cmd', 'scope': '@SUM(A1)', 'detail': '-1+2', 'reason': ' \t=2',
            'params': {'value': '=2'}, 'at': '\t=3'}]}
        output = []
        self.handler.send_data = lambda status, body, *a, **kw: output.append(body)
        self.handler.results_csv(state)
        row = next(csv.DictReader(io.StringIO(output[0])))
        for key in ('agent_id', 'grant_id', 'scope', 'detail', 'reason', 'at'):
            self.assertTrue(row[key].startswith("'"), key)
        self.assertEqual(row['line'], '1')

    def test_typed_grant_fields_and_plain_language_snapshot_preview(self):
        self.handler.grants_page(self.token, self.state)
        body = self.pages[-1][1]
        self.assertIn('name="limit:crm.contacts:read:max_records"', body)
        self.assertIn('allowed values, one per line', body)
        self.assertNotIn('name="limits"', body)
        form = {'agent_id': ['agt_new'], 'subject_ref': ['sub_new'], 'scopes': ['crm.contacts:read'],
            'minutes': ['60'], 'purpose': ['Read'], 'limit:crm.contacts:read:max_records': ['10'],
            'limit:crm.contacts:read:allowed_region': ['us\nca']}
        self.handler.issue(self.token, self.state, form)
        grant = list(self.state['grants'].values())[-1]
        self.assertEqual(grant['limits'], {'max_records': 10, 'allowed_region': ['us', 'ca']})
        self.store.update_catalogue(self.state, {'scopes': {}})
        self.handler.grant_page(self.token, self.state, grant['grant_id'])
        body = self.pages[-1][1]
        self.assertIn('Read contacts', body)
        self.assertIn('records must be at most 10', body)
        self.assertIn('region must be one of: us, ca', body)

    def test_bookmark_explains_view_only_retention_including_sample(self):
        token = self.store.create(sample=True)
        state = self.store.load(token)
        self.handler.dashboard(token, state)
        self.assertIn('24 hours', self.pages[-1][2]['banner'])
        self.assertIn('viewing does not extend', self.pages[-1][2]['banner'])
        self.now[0] += 86401
        self.store.load(token)
        self.store.sweep()
        with self.assertRaises(StoreError):
            self.store.load(token)

    def test_storage_accounting_no_full_scan_on_save_delete_and_restart(self):
        with patch.object(self.store, '_total_bytes', side_effect=AssertionError('full scan')):
            self.store.save(self.token, self.state)
            another = self.store.create()
            self.store.delete(another)
            self.now[0] += 31 * 86400
            self.store.sweep()
        self.assertEqual(self.store.total_bytes, self.store._total_bytes())
        restarted = WorkspaceStore(self.temp.name, clock=lambda: self.now[0])
        self.assertEqual(restarted.total_bytes, self.store.total_bytes)

    def test_storage_cap_check_and_write_share_one_lock(self):
        self.store.data_cap = self.store.total_bytes + 2
        before = self.store.total_bytes
        with self.assertRaisesRegex(StoreError, 'global_data_capacity_reached'):
            self.store._write_bytes(self.store.root / 'too-large', b'123')
        self.assertEqual(before, self.store.total_bytes)
        self.assertFalse((self.store.root / 'too-large').exists())
        self.store.delete(self.token)
        self.assertEqual(self.store.total_bytes, self.store._total_bytes())

    def test_per_ip_creation_limit_preserves_room_for_other_clients(self):
        for _ in range(10):
            self.store.create(client_ip='192.0.2.1')
        for _ in range(3):
            with self.assertRaisesRegex(StoreError, 'ip_rate_reached'):
                self.store.create(client_ip='192.0.2.1')
        other = self.store.create(client_ip='192.0.2.2')
        self.assertIsNotNone(self.store.load(other))
        self.now[0] += 3600
        self.store.create(client_ip='192.0.2.1')

    def set_upload(self, payload):
        boundary = 'test-boundary'
        raw = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="actions.jsonl"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode()
               + payload + f'\r\n--{boundary}--\r\n'.encode())
        headers = Message()
        headers['Content-Type'] = 'multipart/form-data; boundary=' + boundary
        headers['Content-Length'] = str(len(raw))
        self.handler.headers = headers
        self.handler.rfile = io.BytesIO(raw)

    def test_exact_one_mb_file_accepts_multipart_overhead(self):
        payload = b'{}' + b' ' * (app.MAX_BODY - 2)
        self.set_upload(payload)
        form = self.handler.form()
        self.assertEqual(len(form['file'][0].encode()), app.MAX_BODY)
        self.assertEqual(len(self.handler.parse_batch(form['file'][0], '', 'jsonl')), 1)
        self.set_upload(payload + b' ')
        with self.assertRaisesRegex(StoreError, 'body_too_large'):
            self.handler.form()

    def test_atomic_replace_fsyncs_parent_after_replace(self):
        events = []
        real_replace = app.os.replace
        def replace(source, destination):
            events.append('replace')
            return real_replace(source, destination)
        with patch('grantline.store.os.replace', side_effect=replace), patch.object(self.store, '_fsync_directory', side_effect=lambda directory: events.append('directory')):
            self.store.save(self.token, self.state)
        self.assertEqual(events, ['replace', 'directory'])

    def test_sweep_reads_state_only_after_taking_workspace_lock(self):
        self.now[0] += 91 * 86400
        original = self.store.lock_for
        refreshed = []
        @contextmanager
        def locking(key):
            with original(key):
                if not refreshed and key == self.store.key(self.token):
                    refreshed.append(True)
                    # Simulate a writer finishing just before sweep acquires the lock.
                    value = copy.deepcopy(self.state)
                    value.pop('chain_on_load', None)
                    value['last_write'] = self.now[0]
                    self.store._write_json(self.store.ws_root / key / 'state.json', value)
                yield
        with patch.object(self.store, 'lock_for', locking):
            self.store.sweep()
        self.assertEqual(self.store.load(self.token)['last_write'], self.now[0])


class WorkerDeadlineTests(unittest.TestCase):
    def test_deadline_keeps_slot_until_handler_actually_finishes(self):
        server = object.__new__(app.AppServer)
        server.slots = threading.BoundedSemaphore(1)
        server.request_timeout = 10
        self.assertTrue(server.slots.acquire(blocking=False))
        closed = []
        connection = SimpleNamespace(shutdown=lambda how: closed.append(how))
        timers = []
        test = self
        class Timer:
            def __init__(self, duration, callback):
                self.callback = callback
                self.cancelled = False
                timers.append(self)
            def start(self):
                self.callback()
            def cancel(self):
                self.cancelled = True
        def slow_handler(*args):
            test.assertEqual(closed, [socket.SHUT_RDWR])
            test.assertFalse(server.slots.acquire(blocking=False))
            with patch.object(app.ThreadingHTTPServer, 'process_request') as start, patch.object(server, 'shutdown_request') as close:
                server.process_request(object(), ('127.0.0.1', 2))
                start.assert_not_called()
                close.assert_called_once()
        with patch.object(app.threading, 'Timer', Timer), patch.object(app.ThreadingHTTPServer, 'process_request_thread', side_effect=slow_handler):
            server.process_request_thread(connection, ('127.0.0.1', 1))
        self.assertTrue(timers[0].cancelled)
        self.assertTrue(server.slots.acquire(blocking=False))


if __name__ == '__main__':
    unittest.main()
