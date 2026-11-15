import unittest
from grantline import Workspace


class Clock:
    def __init__(self): self.now = 1000.0
    def __call__(self): return self.now


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.ws = Workspace(clock=self.clock)
        req = self.ws.request_grant("agt_budget_buddy", "sub_test", ("bank.transactions:read",), {"max_lookback_days": 90}, "Test summary", 60)
        self.grant = self.ws.approve(req.request_id, "sub_test")

    def test_decisions(self):
        self.assertEqual(self.ws.check("agt_budget_buddy", self.grant.grant_id, "bank.transactions:read", {"lookback_days": 60}).reason, "ok")
        self.assertEqual(self.ws.check("agt_budget_buddy", self.grant.grant_id, "bank.transactions:read", {"lookback_days": 365}).reason, "lookback_exceeds_limit")
        self.assertEqual(self.ws.check("agt_budget_buddy", self.grant.grant_id, "bank.payments:initiate", {}).reason, "scope_forbidden")
        self.assertEqual(self.ws.check("agt_trip_planner", self.grant.grant_id, "bank.transactions:read", {}).reason, "agent_mismatch")
        self.assertEqual(self.ws.check("agt_budget_buddy", self.grant.grant_id, "bank.accounts:read", {}).reason, "scope_not_granted")

    def test_f3_missing_lookback_is_denied_and_audited(self):
        for params in ({}, {"account_type": "checking"}, {"secret": "drop"}):
            with self.subTest(params=params):
                decision = self.ws.check(
                    "agt_budget_buddy", self.grant.grant_id,
                    "bank.transactions:read", params
                )
                self.assertFalse(decision.allow)
                self.assertEqual(decision.reason, "params_invalid")
                self.assertEqual(decision.detail, "lookback_days required")
                event = self.ws.audit.events()[-1]
                self.assertEqual(event["event"], "action.checked")
                self.assertFalse(event["data"]["allow"])
                self.assertEqual(event["data"]["reason"], "params_invalid")
                self.assertEqual(event["data"]["params"], {})
                self.assertEqual(event["data"]["dropped_params"], len(params))
        self.assertEqual(self.ws.audit.verify(), (True, None))

    def test_f3_explicit_lookback_boundaries(self):
        for days, allow, reason in (
            (0, True, "ok"),
            (90, True, "ok"),
            (91, False, "lookback_exceeds_limit"),
            (3650, False, "lookback_exceeds_limit"),
        ):
            with self.subTest(days=days):
                decision = self.ws.check(
                    "agt_budget_buddy", self.grant.grant_id,
                    "bank.transactions:read", {"lookback_days": days}
                )
                self.assertEqual(decision.allow, allow)
                self.assertEqual(decision.reason, reason)

    def test_f3_invalid_lookback_cannot_replace_required_integer(self):
        for value in (None, False, True, "90", 90.0, -1, 3651, [], {}):
            with self.subTest(value=value):
                decision = self.ws.check(
                    "agt_budget_buddy", self.grant.grant_id,
                    "bank.transactions:read", {"lookback_days": value}
                )
                self.assertFalse(decision.allow)
                self.assertEqual(decision.reason, "params_invalid")
                self.assertEqual(
                    decision.detail,
                    "lookback_days must be an integer from 0 to 3650"
                )

    def test_f3_accounts_do_not_require_lookback(self):
        request = self.ws.request_grant(
            "agt_budget_buddy", "sub_test", ("bank.accounts:read",),
            {}, "List accounts", 60
        )
        grant = self.ws.approve(request.request_id, "sub_test")
        decision = self.ws.check(
            "agt_budget_buddy", grant.grant_id, "bank.accounts:read", {}
        )
        self.assertTrue(decision.allow)
        self.assertEqual(decision.reason, "ok")

    def test_expiry_once(self):
        self.clock.now += 61
        self.assertEqual(self.ws.check("agt_budget_buddy", self.grant.grant_id, "bank.transactions:read", {}).reason, "grant_expired")
        self.ws.check("agt_budget_buddy", self.grant.grant_id, "bank.transactions:read", {})
        self.assertEqual(sum(e["event"] == "grant.expired" for e in self.ws.audit.events()), 1)

    def test_validation_codes(self):
        cases = [
            (("bank.payments:initiate",), "ok", 60, "sub_test", "scope_forbidden"),
            (("airline.itineraries:read",), "ok", 60, "sub_test", "target_unavailable"),
            (("unknown:read",), "ok", 60, "sub_test", "scope_unknown"),
            (("bank.accounts:read",), "", 60, "sub_test", "purpose_invalid"),
            (("bank.accounts:read",), "ok", 1, "sub_test", "ttl_out_of_range"),
            (("bank.accounts:read",), "ok", 60, "bad", "subject_ref_invalid"),
        ]
        for scopes, purpose, ttl, subject, code in cases:
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, code):
                self.ws.request_grant("agt_budget_buddy", subject, scopes, {}, purpose, ttl)


if __name__ == "__main__": unittest.main()
