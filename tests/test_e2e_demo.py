"""Full HTTP adapter and SDK flow through in-memory sockets; no network."""
import io
import json
import re
import socket
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlencode

import demo
from grantline import Workspace, FakeAggregatorConnector, FakeVault

AGENT = "agt_budget_buddy"
SCOPE = "bank.transactions:read"


class MemorySocket:
    def __init__(self, request):
        self.input = io.BytesIO(request)
        self.output = bytearray()

    def makefile(self, *args, **kwargs):
        return self.input

    def sendall(self, value):
        self.output.extend(value)

    def settimeout(self, value):
        pass


class E2EDemoTests(unittest.TestCase):
    def setUp(self):
        self.table = demo.SessionTable()
        self.patch = patch.object(demo, "SESSIONS", self.table)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        # Any accidental socket creation in this entire HTTP/SDK test fails.
        self.network = patch.object(socket, "socket", side_effect=AssertionError("network forbidden"))
        self.network.start()
        self.addCleanup(self.network.stop)
        self.server = SimpleNamespace(secure_cookie=False,
                                      allowed_origins={"http://localhost:8080"})
        self.cookie = None

    def request(self, method, path, values=None, *, json_body=False, headers=None):
        headers = dict(headers or {})
        headers.setdefault("Host", "localhost:8080")
        raw = b""
        if values is not None:
            raw = (json.dumps(values) if json_body else urlencode(values)).encode()
            headers["Content-Type"] = "application/json" if json_body else "application/x-www-form-urlencoded"
            headers["Content-Length"] = str(len(raw))
        if self.cookie:
            headers["Cookie"] = self.cookie
        prefix = f"{method} {path} HTTP/1.0\r\n" + ''.join(f"{key}: {value}\r\n" for key, value in headers.items()) + "\r\n"
        connection = MemorySocket(prefix.encode() + raw)
        demo.DemoHandler(connection, ("127.0.0.1", 12345), self.server)
        head, body = bytes(connection.output).split(b"\r\n\r\n", 1)
        lines = head.decode().split("\r\n")
        status = int(lines[0].split()[1])
        result_headers = dict(line.split(": ", 1) for line in lines[1:])
        if "Set-Cookie" in result_headers:
            self.cookie = result_headers["Set-Cookie"].split(";", 1)[0]
        return status, result_headers, body

    def start(self):
        status, _, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        csrf = re.search(rb'name="csrf" value="([^"]+)"', body).group(1).decode()
        session = self.table.rows[self.cookie.split("=", 1)[1]]
        return csrf, session

    def test_full_core_flow_with_fakes_and_no_network(self):
        csrf, session = self.start()
        self.assertIsInstance(session.ws.vault, FakeVault)
        connector = session.ws.connectors["fake_aggregator"]
        self.assertIsInstance(connector, FakeAggregatorConnector)
        auth = {"Authorization": "Bearer " + session.api_tokens[AGENT], "X-Grantline-API": "1"}
        payload = {"agent_id": AGENT, "subject_ref": demo.SUBJECT, "scopes": [SCOPE],
                   "limits": {"max_lookback_days": 90}, "purpose": "Monthly <summary>",
                   "ttl_seconds": 30 * 86400}
        status, _, body = self.request("POST", "/api/v1/grant-requests", payload, json_body=True, headers=auth)
        self.assertEqual(status, 201, body)
        request_id = json.loads(body)["request_id"]
        consent = "/consent/" + request_id
        status, _, body = self.request("GET", consent)
        self.assertEqual(status, 200)
        for value in (b"Budget Buddy", b"Sample User A", b"90", b"30.0 days", b"Monthly &lt;summary&gt;"):
            self.assertIn(value, body)
        contact = "invented-e2e@example.invalid"
        status, headers, body = self.request("POST", consent + "/approve", {"csrf": csrf, "contact": contact})
        self.assertEqual(status, 303, body)
        grant_id = headers["Location"].split("#")[1]
        grant = session.ws.grants[grant_id]
        self.assertEqual(connector.status(grant.connection_ref), "linked")
        self.assertTrue(grant.contact_ref.startswith("vlt_"))
        self.assertNotIn(contact, repr(vars(session.ws.vault)))
        check = {"agent_id": AGENT, "grant_id": grant_id, "scope": SCOPE}
        for scope, params, allow, reason in (
            (SCOPE, {"lookback_days": 60}, True, "ok"),
            (SCOPE, {"lookback_days": 365}, False, "lookback_exceeds_limit"),
            ("bank.payments:initiate", {}, False, "scope_forbidden"),
            (SCOPE, {}, False, "params_invalid"),
        ):
            status, _, body = self.request("POST", "/api/v1/check", dict(check, scope=scope, params=params), json_body=True, headers=auth)
            self.assertEqual(status, 200, body)
            decision = json.loads(body)
            self.assertEqual((decision["allow"], decision["reason"]), (allow, reason))
        status, _, _ = self.request("POST", "/connector/failure", {"csrf": csrf, "enabled": "on"})
        self.assertEqual(status, 303)
        status, _, body = self.request("POST", f"/grants/{grant_id}/revoke", {"csrf": csrf})
        self.assertEqual(status, 303, body)
        self.assertTrue(grant.hook_pending)
        self.assertIn(b"provider confirmation pending", self.request("GET", "/grants")[2])
        status, _, body = self.request("POST", "/api/v1/check", dict(check, params={"lookback_days": 60}), json_body=True, headers=auth)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["reason"], "grant_revoked")
        self.request("POST", "/connector/failure", {"csrf": csrf})
        status, _, _ = self.request("POST", f"/grants/{grant_id}/retry", {"csrf": csrf})
        self.assertEqual(status, 303)
        self.assertFalse(grant.hook_pending)
        self.assertEqual(connector.status(grant.connection_ref), "revoked")
        # Denial is also a complete browser flow, with no provider link.
        status, _, body = self.request("POST", "/api/v1/grant-requests", payload, json_body=True, headers=auth)
        self.assertEqual(status, 201)
        denied_id = json.loads(body)["request_id"]
        self.assertEqual(self.request("POST", f"/consent/{denied_id}/deny", {"csrf": csrf})[0], 303)
        self.assertEqual(session.ws.requests[denied_id].status, "denied")
        self.assertEqual(self.request("POST", f"/consent/{denied_id}/approve", {"csrf": csrf})[0], 400)
        audit = json.loads(self.request("GET", "/api/v1/audit")[2])
        self.assertTrue(audit["chain_ok"])
        self.assertEqual({e["actor_type"] for e in audit["events"]}, {"agent", "human", "system"})
        names = [e["event"] for e in audit["events"]]
        for event in ("grant.requested", "grant.approved", "grant.issued", "action.checked", "grant.revoked", "connector.revoke_hook", "grant.denied"):
            self.assertIn(event, names)
        hooks = [e["data"]["outcome"] for e in audit["events"] if e["event"] == "connector.revoke_hook"]
        self.assertEqual(hooks, ["failed", "ok"])
        self.assertEqual(audit["event_count"], len(audit["events"]))
        for path in ("/", "/dev", "/grants", "/agent", "/audit", "/api/v1/audit", consent):
            self.assertNotIn(contact.encode(), self.request("GET", path)[2])
        bad_seq = len(audit["events"]) // 2 + 1
        self.assertEqual(self.request("POST", "/audit/tamper", {"csrf": csrf})[0], 303)
        audit = json.loads(self.request("GET", "/api/v1/audit")[2])
        self.assertFalse(audit["chain_ok"])
        self.assertEqual(audit["first_bad_seq"], bad_seq)
        self.assertIn(f"Chain broken at sequence {bad_seq}".encode(), self.request("GET", "/audit")[2])

    def test_both_auth_modes_and_no_bearer_downgrade(self):
        csrf, session = self.start()
        grant_id = next(iter(session.ws.grants))
        data = {"agent_id": AGENT, "grant_id": grant_id, "scope": "bank.accounts:read", "params": {}}
        for headers, expected in (
            ({}, 403),
            ({"X-CSRF-Token": "wrong"}, 403),
            ({"X-CSRF-Token": csrf}, 200),
            ({"X-CSRF-Token": csrf, "Authorization": "Bearer wrong", "X-Grantline-API": "1"}, 401),
            ({"Authorization": "Bearer " + session.api_tokens[AGENT]}, 403),
            ({"Authorization": "Bearer " + session.api_tokens[AGENT], "X-Grantline-API": "1"}, 200),
            ({"X-CSRF-Token": csrf, "Origin": "https://evil.invalid", "Host": "evil.invalid"}, 403),
        ):
            with self.subTest(headers=headers):
                self.assertEqual(self.request("POST", "/api/v1/check", data, json_body=True, headers=headers)[0], expected)
        headers = {"Authorization": "Bearer " + session.api_tokens[AGENT], "X-Grantline-API": "1"}
        self.assertEqual(self.request("POST", "/api/v1/check", dict(data, agent_id="agt_trip_planner"), json_body=True, headers=headers)[0], 403)

    def test_capacity_error_is_visible_and_no_approval_side_effects(self):
        csrf, session = self.start()
        ws = Workspace(max_events=2)
        session.ws = ws
        req = ws.request_grant(AGENT, demo.SUBJECT, [SCOPE], {"max_lookback_days": 90}, "Summary", 600)
        status, _, body = self.request("POST", f"/consent/{req.request_id}/approve", {"csrf": csrf, "contact": "fake@example.invalid"})
        self.assertEqual(status, 409)
        self.assertIn(b"Audit capacity reached", body)
        self.assertEqual(ws.requests[req.request_id].status, "pending")
        self.assertFalse(ws.grants)
        self.assertFalse(ws.vault._records)
        self.assertFalse(ws.connectors["fake_aggregator"]._connections)
        self.assertIn(b"Approval requires two", self.request("GET", "/audit")[2])
        ws.audit.append("test.fill", "system", "system", demo.SUBJECT)
        status, _, body = self.request("POST", "/api/v1/check", {"agent_id": AGENT}, json_body=True, headers={"X-CSRF-Token": csrf})
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body)["error"], "audit_capacity_reached")

    def test_session_flood_cannot_evict_existing_visitor(self):
        self.table.limit = 1
        csrf, session = self.start()
        cookie = self.cookie
        self.cookie = None
        for _ in range(5):
            self.assertEqual(self.request("GET", "/")[0], 503)
        self.assertEqual(self.request("GET", "/healthz")[0], 200)
        self.cookie = cookie
        self.assertEqual(self.request("GET", "/")[0], 200)
        self.assertIs(self.table.rows[cookie.split("=", 1)[1]], session)
        self.assertEqual(session.csrf, csrf)

    def test_secure_cookie_configuration(self):
        self.server.secure_cookie = True
        _, headers, _ = self.request("GET", "/")
        self.assertIn("; Secure", headers["Set-Cookie"])


class AuditCapacityTests(unittest.TestCase):
    def test_full_and_one_slot_left_approval_are_atomic(self):
        for maximum in (1, 2):
            with self.subTest(maximum=maximum):
                ws = Workspace(max_events=maximum)
                req = ws.request_grant(AGENT, "sub_x", ["bank.accounts:read"], {}, "List", 600)
                before = ws.audit.events()
                with self.assertRaisesRegex(RuntimeError, "audit_capacity_reached"):
                    ws.approve(req.request_id, "sub_x", "fake@example.invalid")
                self.assertEqual(ws.audit.events(), before)
                self.assertEqual(ws.requests[req.request_id].status, "pending")
                self.assertEqual(ws.grants, {})
                self.assertEqual(ws.connectors["fake_aggregator"]._connections, {})
                self.assertEqual(ws.vault._records, {})
                self.assertEqual(ws.audit.verify(), (True, None))

    def test_request_and_denial_fail_without_mutation(self):
        ws = Workspace(max_events=1)
        req = ws.request_grant(AGENT, "sub_x", ["bank.accounts:read"], {}, "List", 600)
        with self.assertRaisesRegex(RuntimeError, "audit_capacity_reached"):
            ws.request_grant(AGENT, "sub_x", ["bank.accounts:read"], {}, "List", 600)
        with self.assertRaisesRegex(RuntimeError, "audit_capacity_reached"):
            ws.deny(req.request_id, "sub_x")
        self.assertEqual(list(ws.requests), [req.request_id])
        self.assertEqual(ws.requests[req.request_id].status, "pending")

    def test_revocation_and_emergency_retry_remain_audited_at_capacity(self):
        ws = Workspace(max_events=3)
        req = ws.request_grant(AGENT, "sub_x", ["bank.accounts:read"], {}, "List", 600)
        grant = ws.approve(req.request_id, "sub_x")
        connector = ws.connectors["fake_aggregator"]
        connector.fail_revoke = True
        ws.revoke(grant.grant_id, actor_id="sub_x")
        connector.fail_revoke = False
        ws.retry_hook(grant.grant_id)
        self.assertEqual([event["event"] for event in ws.audit.events()][-3:],
                         ["grant.revoked", "connector.revoke_hook", "connector.revoke_hook"])
        self.assertEqual(ws.audit.verify(), (True, None))
        self.assertFalse(grant.hook_pending)
        self.assertEqual(connector.status(grant.connection_ref), "revoked")

    def test_repeated_failed_retries_cannot_consume_other_grants_reserve(self):
        ws = Workspace(max_events=6, max_grants=2)
        grants = []
        for _ in range(2):
            req = ws.request_grant(AGENT, "sub_x", ["bank.accounts:read"], {}, "List", 600)
            grants.append(ws.approve(req.request_id, "sub_x"))
        connector = ws.connectors["fake_aggregator"]
        connector.fail_revoke = True
        ws.revoke(grants[0].grant_id, actor_id="sub_x")
        ws.retry_hook(grants[0].grant_id)
        count = ws.audit.event_count
        with self.assertRaisesRegex(RuntimeError, "audit_capacity_reached"):
            ws.retry_hook(grants[0].grant_id)
        self.assertEqual(ws.audit.event_count, count)
        connector.fail_revoke = False
        ws.revoke(grants[1].grant_id, actor_id="sub_x")
        self.assertEqual(connector.status(grants[1].connection_ref), "revoked")
        self.assertEqual(ws.audit.verify(), (True, None))

    def test_expiry_is_recorded_once_even_when_ordinary_log_is_full(self):
        now = [1000.0]
        ws = Workspace(clock=lambda: now[0], max_events=4)
        req = ws.request_grant(AGENT, "sub_x", ["bank.accounts:read"], {}, "List", 60)
        grant = ws.approve(req.request_id, "sub_x")
        pending = ws.request_grant(AGENT, "sub_x", ["bank.accounts:read"], {}, "List", 60)
        now[0] += 61
        ws.list_grants("sub_x")
        ws.list_grants("sub_x")
        with self.assertRaisesRegex(ValueError, "request_expired"):
            ws.approve(pending.request_id, "sub_x")
        self.assertEqual(grant.status, "expired")
        events = [e["event"] for e in ws.audit.events()]
        self.assertEqual(events.count("grant.expired"), 1)
        self.assertEqual(events.count("grant.request_expired"), 1)
        self.assertEqual(ws.audit.verify(), (True, None))


class ServerBoundsTests(unittest.TestCase):
    def server_stub(self):
        server = object.__new__(demo.BoundedServer)
        server.slots = threading.BoundedSemaphore(1)
        server.request_timeout = 10
        return server

    def test_connection_limit_rejects_without_starting_another_thread(self):
        server = self.server_stub()
        connection = object()
        with patch.object(demo.ThreadingHTTPServer, "process_request") as start, patch.object(server, "shutdown_request") as close:
            server.process_request(connection, ("127.0.0.1", 1))
            server.process_request(connection, ("127.0.0.1", 2))
            self.assertEqual(start.call_count, 1)
            close.assert_called_once_with(connection)

    def test_absolute_deadline_closes_socket_and_releases_slot(self):
        server = self.server_stub()
        server.slots.acquire()
        connection = SimpleNamespace(shutdown=lambda how: closed.append(how))
        closed = []
        timers = []

        class Timer:
            def __init__(self, duration, callback):
                self.duration, self.callback, self.cancelled = duration, callback, False
                timers.append(self)

            def start(self):
                self.callback()

            def cancel(self):
                self.cancelled = True

        with patch.object(demo.threading, "Timer", Timer), patch.object(demo.ThreadingHTTPServer, "process_request_thread"):
            server.process_request_thread(connection, ("127.0.0.1", 1))
        self.assertEqual(closed, [socket.SHUT_RDWR])
        self.assertEqual(timers[0].duration, 10)
        self.assertTrue(timers[0].cancelled)
        self.assertTrue(server.slots.acquire(blocking=False))


if __name__ == "__main__":
    unittest.main()
