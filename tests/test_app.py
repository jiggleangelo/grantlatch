import hashlib
import http.client
import json
import tempfile
import threading
import unittest
from urllib.parse import urlencode, urlsplit

import app
from grantline.store import canonical


class AppTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.server = app.make_server("127.0.0.1", 0, data_dir=self.temp.name)
        self.port = self.server.server_port
        self.origin = self.server.public_base_url
        self.host = urlsplit(self.origin).netloc
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.temp.cleanup()

    def request(self, method, path, values=None, headers=None):
        headers = dict(headers or {})
        headers.setdefault("Host", self.host)
        body = None
        if values is not None:
            body = urlencode(values, doseq=True)
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            headers.setdefault("Origin", self.origin)
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def create(self, sample=False):
        status, headers, _ = self.request("POST", "/w", {"sample": "1" if sample else "0"})
        self.assertEqual(status, 303)
        return urlsplit(headers["Location"]).path.split("/")[2]

    def post(self, token, suffix, values):
        return self.request("POST", f"/w/{token}{suffix}", values)

    def test_health_security_notice_and_token_not_stored(self):
        self.assertEqual(self.request("GET", "/healthz")[0::2], (200, b"ok"))
        token = self.create()
        for path in ("/", f"/w/{token}", f"/w/{token}/catalogue", f"/w/{token}/grants", f"/w/{token}/audit"):
            body = self.request("GET", path)[2]
            self.assertIn(app.NOTICE.encode(), body)
            self.assertIn(b"manykiln.com/privacy", body)
        for path in self.server.store.root.rglob("*"):
            self.assertNotIn(token, path.name)
            if path.is_file():
                self.assertNotIn(token.encode(), path.read_bytes())
        self.assertEqual(self.request("GET", "/", headers={"Host": "evil.invalid"})[0], 400)
        self.assertEqual(self.request("POST", "/w", {}, {"Origin": "null"})[0], 403)
        self.assertEqual(self.request("POST", "/w", {}, {"Referer": self.origin + "/"})[0], 303)

    def setup_real_workspace(self):
        token = self.create()
        catalogue = {"scopes": {
            "crm.contacts:read": {"label": "Read contacts", "limits": {
                "max_records": {"type": "max", "param": "records"},
                "allowed_region": {"type": "oneof", "param": "region"}
            }},
            "crm.notes:read": {"label": "Read notes", "limits": {}}
        }}
        self.assertEqual(self.post(token, "/catalogue", {"catalogue": json.dumps(catalogue)})[0], 303)
        values = {"agent_id": "agt_reader", "subject_ref": "sub_demo", "scopes": "crm.contacts:read",
                  "limits": json.dumps({"max_records": 50, "allowed_region": ["us", "ca"]}),
                  "purpose": "Test a CRM reader", "minutes": "60"}
        status, headers, body = self.post(token, "/grants", values)
        self.assertEqual(status, 303, body)
        grant_id = urlsplit(headers["Location"]).path.rsplit("/", 1)[1]
        return token, grant_id

    def test_real_flow_batch_revoke_backdate_export_and_delete(self):
        token, grant_id = self.setup_real_workspace()
        state = self.server.store.load(token)
        issued = state["grants"][grant_id]["issued_at"]
        actions = [
            {"agent_id": "agt_reader", "grant_id": grant_id, "scope": "crm.contacts:read", "params": {"records": 20, "region": "us"}},
            {"agent_id": "agt_reader", "grant_id": grant_id, "scope": "crm.contacts:read", "params": {"records": 60, "region": "us"}},
            {"agent_id": "agt_reader", "grant_id": grant_id, "scope": "crm.contacts:read", "params": {"records": 20, "region": "eu"}},
            {"agent_id": "agt_reader", "grant_id": grant_id, "scope": "payments.transfer:create", "params": {}},
            {"agent_id": "agt_other", "grant_id": grant_id, "scope": "crm.contacts:read", "params": {"records": 1, "region": "us"}},
            {"agent_id": "agt_reader", "grant_id": grant_id, "scope": "crm.notes:read", "params": {}}
        ]
        batch = "\n".join(json.dumps(item) for item in actions)
        status, _, body = self.post(token, "/batch", {"format": "jsonl", "batch": batch})
        self.assertEqual(status, 200, body)
        reasons = [item["reason"] for item in self.server.store.load(token)["last_results"]]
        self.assertEqual(reasons[:5], ["ok", "limit_exceeded:max_records", "value_not_allowed:allowed_region", "scope_forbidden", "agent_mismatch"])
        self.assertEqual(self.request("GET", f"/w/{token}/batch/results.csv")[0], 200)
        self.assertEqual(self.post(token, f"/grants/{grant_id}/revoke", {})[0], 200)
        current = {"agent_id": "agt_reader", "grant_id": grant_id, "scope": "crm.contacts:read", "params": {"records": 1, "region": "us"}}
        self.post(token, "/check", {"action": json.dumps(current)})
        self.assertEqual(self.server.store.load(token)["audit"][-1]["data"]["reason"], "grant_revoked")
        revoked = self.server.store.load(token)["grants"][grant_id]["revoked_at"]
        self.assertGreater(revoked, issued)
        current["at"] = app.iso_time((issued + revoked) / 2)
        self.post(token, "/check", {"action": json.dumps(current)})
        self.assertEqual(self.server.store.load(token)["audit"][-1]["data"]["reason"], "ok")
        status, _, raw = self.request("GET", f"/w/{token}/export")
        self.assertEqual(status, 200)
        exported = json.loads(raw)
        previous = "0" * 64
        for event in exported["audit"]:
            candidate = dict(event)
            found = candidate.pop("hash")
            self.assertEqual(found, hashlib.sha256((previous + canonical(candidate)).encode()).hexdigest())
            previous = found
        self.assertTrue(exported["chain_verify"]["ok"])
        self.assertEqual(self.post(token, "/delete", {})[0], 200)
        self.assertEqual(self.request("GET", f"/w/{token}")[0], 404)

    def test_sample_tamper_and_body_limit(self):
        token = self.create(sample=True)
        self.assertIn(b"Chain verifies", self.request("GET", f"/w/{token}/audit")[2])
        self.assertEqual(self.post(token, "/audit/tamper", {})[0], 303)
        self.assertIn(b"Chain broken at sequence", self.request("GET", f"/w/{token}/audit")[2])
        raw = b"x" * (1024 * 1024 + 1)
        status = self.request("POST", "/w", headers={"Origin": self.origin, "Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(raw))})[0]
        self.assertIn(status, (400, 413))

    def test_restart_persistence(self):
        token, grant_id = self.setup_real_workspace()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.server = app.make_server("127.0.0.1", 0, data_dir=self.temp.name)
        self.port = self.server.server_port
        self.origin = self.server.public_base_url
        self.host = urlsplit(self.origin).netloc
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        state = self.server.store.load(token)
        self.assertIn(grant_id, state["grants"])
        self.assertTrue(state["audit"])


if __name__ == "__main__":
    unittest.main()
