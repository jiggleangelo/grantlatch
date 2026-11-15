import json
import unittest
from grantline import Workspace


class GrantAuditTests(unittest.TestCase):
    def test_revoke_failure_is_immediate_and_retryable(self):
        ws = Workspace()
        req = ws.request_grant("agt_budget_buddy", "sub_x", ("bank.accounts:read",), {}, "List accounts", 600)
        grant = ws.approve(req.request_id, "sub_x", "invented@example.invalid")
        ws.connectors["fake_aggregator"].fail_revoke = True
        ws.revoke(grant.grant_id, actor_id="sub_x")
        self.assertTrue(grant.hook_pending)
        self.assertEqual(ws.check("agt_budget_buddy", grant.grant_id, "bank.accounts:read", {}).reason, "grant_revoked")
        ws.connectors["fake_aggregator"].fail_revoke = False
        ws.retry_hook(grant.grant_id)
        self.assertFalse(grant.hook_pending)
        serialized = json.dumps(ws.audit.events())
        self.assertNotIn("@", serialized)
        self.assertNotIn("invented", serialized)

    def test_revoke_and_retry_work_when_audit_is_full(self):
        ws = Workspace(max_events=3)
        req = ws.request_grant(
            "agt_budget_buddy", "sub_x", ("bank.accounts:read",),
            {}, "List accounts", 600
        )
        grant = ws.approve(req.request_id, "sub_x")
        connector = ws.connectors["fake_aggregator"]
        self.assertEqual(len(ws.audit.events()), 3)

        connector.fail_revoke = True
        ws.revoke(grant.grant_id, actor_id="sub_x")
        self.assertEqual(grant.status, "revoked")
        self.assertTrue(grant.hook_pending)
        self.assertEqual(connector.status(grant.connection_ref), "linked")

        connector.fail_revoke = False
        ws.retry_hook(grant.grant_id)
        self.assertFalse(grant.hook_pending)
        self.assertEqual(connector.status(grant.connection_ref), "revoked")
        self.assertEqual(ws.audit.verify(), (True, None))

    def test_chain_and_redaction(self):
        ws = Workspace()
        req = ws.request_grant("agt_budget_buddy", "sub_x", ("bank.transactions:read",), {"max_lookback_days": 90}, "Summary", 600)
        grant = ws.approve(req.request_id, "sub_x")
        ws.check("agt_budget_buddy", grant.grant_id, "bank.transactions:read", {"lookback_days": 2, "secret": "drop"})
        event = ws.audit.events()[-1]
        self.assertEqual(event["data"]["dropped_params"], 1)
        self.assertNotIn("secret", event["data"]["params"])
        self.assertEqual(ws.audit.verify(), (True, None))

        # Corrupt stored data only in the test; production needs no tamper API.
        stored_event = ws.audit._events[-1]
        seq = stored_event["seq"]
        stored_event["data"]["allow"] = False
        self.assertEqual(ws.audit.verify(), (False, seq))

    def test_deny_cannot_be_approved(self):
        ws = Workspace()
        req = ws.request_grant("agt_budget_buddy", "sub_x", ("bank.accounts:read",), {}, "List", 600)
        ws.deny(req.request_id, "sub_x")
        with self.assertRaisesRegex(ValueError, "request_not_pending"):
            ws.approve(req.request_id, "sub_x")


if __name__ == "__main__": unittest.main()
