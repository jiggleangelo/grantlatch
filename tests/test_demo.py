import http.client
import json
import re
import threading
import unittest
from urllib.parse import urlencode

import demo


class DemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        demo.SESSIONS = demo.SessionTable()
        cls.server = demo.make_server("127.0.0.1", 0)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(1)

    def setUp(self):
        self.cookie = None

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        headers = dict(headers or {})
        if self.cookie:
            headers["Cookie"] = self.cookie
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        data = response.read()
        if response.getheader("Set-Cookie"):
            self.cookie = response.getheader("Set-Cookie").split(";", 1)[0]
        result = response.status, dict(response.getheaders()), data
        conn.close()
        return result

    def page(self, path):
        return self.request("GET", path)

    def csrf(self):
        status, _, body = self.page("/")
        self.assertEqual(status, 200)
        token = re.search(rb'name="csrf" value="([^"]+)"', body)
        self.assertIsNotNone(token)
        return token.group(1).decode()

    def post_form(self, path, values):
        raw = urlencode(values)
        return self.request("POST", path, raw, {"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(raw))})

    def post_json(self, path, values, csrf=None):
        raw = json.dumps(values).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(raw)),
        }
        if csrf is not None:
            headers["X-CSRF-Token"] = csrf
        return self.request("POST", path, raw, headers)

    def test_health_banner_and_security(self):
        status, _, body = self.page("/healthz")
        self.assertEqual((status, body), (200, b"ok"))
        for path in ("/", "/dev", "/grants", "/agent", "/audit"):
            self.assertIn(demo.BANNER.encode(), self.page(path)[2])
        status, _, _ = self.post_form("/reset", {"csrf": "wrong"})
        self.assertEqual(status, 403)
        status, _, _ = self.request("POST", "/reset", b"x" * 70000, {"Content-Type": "application/x-www-form-urlencoded", "Content-Length": "70000"})
        self.assertEqual(status, 413)

    def test_core_flow(self):
        csrf = self.csrf()
        values = {"csrf": csrf, "agent_id": "agt_budget_buddy", "subject_ref": "sub_demo_user_a", "scope_bank.transactions:read": "on", "lookback": "90", "ttl_days": "30", "purpose": "<script>alert(1)</script>"}
        status, headers, _ = self.post_form("/dev/requests", values)
        self.assertEqual(status, 303)
        consent = headers["Location"]
        page = self.page(consent)[2]
        self.assertIn(b"&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertNotIn(b"<script>alert(1)</script>", page)
        status, _, _ = self.post_form(consent + "/approve", {"csrf": csrf, "contact": "madeup@example.invalid"})
        self.assertEqual(status, 303)
        grants_page = self.page("/grants")[2]
        grant_ids = re.findall(rb"gr_[0-9a-f]{16}", grants_page)
        self.assertTrue(grant_ids)
        grant_id = grant_ids[-1].decode()
        payload = {"agent_id": "agt_budget_buddy", "grant_id": grant_id, "scope": "bank.transactions:read", "params": {"lookback_days": 60}}

        for token in (None, "wrong"):
            with self.subTest(csrf=token):
                status, _, body = self.post_json("/api/v1/check", payload, token)
                self.assertEqual(status, 403, body)

        status, _, body = self.post_json("/api/v1/check", payload, csrf)
        self.assertEqual(status, 200, body)
        self.assertTrue(json.loads(body)["allow"])

        missing_lookback = dict(payload, params={})
        status, _, body = self.post_json("/api/v1/check", missing_lookback, csrf)
        self.assertEqual(status, 200, body)
        decision = json.loads(body)
        self.assertFalse(decision["allow"])
        self.assertEqual(decision["reason"], "params_invalid")
        self.assertEqual(decision["detail"], "lookback_days required")
        audit = json.loads(self.page("/api/v1/audit")[2])
        checked = [event for event in audit["events"] if event["event"] == "action.checked"]
        self.assertTrue(checked)
        self.assertFalse(checked[-1]["data"]["allow"])
        self.assertEqual(checked[-1]["data"]["reason"], "params_invalid")

        status, _, body = self.post_form(f"/grants/{grant_id}/revoke", {"csrf": csrf})
        self.assertEqual(status, 303, body)
        status, _, body = self.post_json("/api/v1/check", payload, csrf)
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["reason"], "grant_revoked")
        audit = json.loads(self.page("/api/v1/audit")[2])
        self.assertTrue(audit["chain_ok"])
        self.assertEqual({"agent", "human", "system"}, {e["actor_type"] for e in audit["events"]})
        self.assertNotIn("@", json.dumps(audit))

    def test_sessions_are_isolated(self):
        first_cookie = self.cookie
        self.page("/")
        first_cookie = self.cookie
        other = DemoTests(methodName="runTest")
        other.port = self.port
        other.cookie = None
        other.page("/")
        self.assertNotEqual(first_cookie, other.cookie)


if __name__ == "__main__": unittest.main()
