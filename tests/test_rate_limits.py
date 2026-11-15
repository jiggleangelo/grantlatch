import unittest

from grantline import Workspace


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class RateLimitTests(unittest.TestCase):
    def request_accounts(self, workspace, agent_id="agt_budget_buddy"):
        return workspace.request_grant(
            agent_id, "sub_x", ("bank.accounts:read",),
            {}, "List accounts", 600
        )

    def test_f2_check_flood_cannot_block_revoke_or_retry(self):
        for actor_type in ("human", "system"):
            with self.subTest(actor_type=actor_type):
                clock = Clock()
                workspace = Workspace(clock=clock, rate_limit=3)
                request = self.request_accounts(workspace)
                grant = workspace.approve(request.request_id, "sub_x")
                connector = workspace.connectors["fake_aggregator"]
                actor = {"actor_type": actor_type}
                if actor_type == "human":
                    actor["actor_subject_ref"] = "sub_x"
                else:
                    actor["actor_id"] = "system"

                for _ in range(2):
                    self.assertTrue(workspace.check(
                        "agt_budget_buddy", grant.grant_id,
                        "bank.accounts:read", {}
                    ).allow)
                for _ in range(5):
                    with self.assertRaisesRegex(RuntimeError, "^rate_limit_exceeded$"):
                        workspace.check(
                            "agt_budget_buddy", grant.grant_id,
                            "bank.accounts:read", {}
                        )

                connector.fail_revoke = True
                workspace.revoke(grant.grant_id, **actor)
                self.assertEqual(grant.status, "revoked")
                self.assertEqual(grant.revoked_at, clock.now)
                self.assertEqual(grant.revoked_by, actor_type)
                self.assertTrue(grant.hook_pending)
                self.assertEqual(connector.status(grant.connection_ref), "linked")

                workspace.retry_hook(grant.grant_id, **actor)
                self.assertTrue(grant.hook_pending)
                connector.fail_revoke = False
                workspace.retry_hook(grant.grant_id, **actor)
                self.assertFalse(grant.hook_pending)
                self.assertEqual(connector.status(grant.connection_ref), "revoked")
                self.assertEqual(workspace.audit.verify(), (True, None))

                clock.now += 60
                decision = workspace.check(
                    "agt_budget_buddy", grant.grant_id,
                    "bank.accounts:read", {}
                )
                self.assertFalse(decision.allow)
                self.assertEqual(decision.reason, "grant_revoked")

    def test_f2_agent_operations_share_only_their_own_bucket(self):
        clock = Clock()
        workspace = Workspace(clock=clock, rate_limit=2)
        first = self.request_accounts(workspace)
        grant = workspace.approve(first.request_id, "sub_x")
        self.assertTrue(workspace.check(
            "agt_budget_buddy", grant.grant_id, "bank.accounts:read", {}
        ).allow)

        with self.assertRaisesRegex(RuntimeError, "^rate_limit_exceeded$"):
            self.request_accounts(workspace)
        with self.assertRaisesRegex(RuntimeError, "^rate_limit_exceeded$"):
            workspace.check(
                "agt_budget_buddy", grant.grant_id, "bank.accounts:read", {}
            )

        second = self.request_accounts(workspace, "agt_trip_planner")
        second_grant = workspace.approve(second.request_id, "sub_x")
        self.assertTrue(workspace.check(
            "agt_trip_planner", second_grant.grant_id, "bank.accounts:read", {}
        ).allow)
        with self.assertRaisesRegex(RuntimeError, "^rate_limit_exceeded$"):
            self.request_accounts(workspace, "agt_trip_planner")

        clock.now += 59
        with self.assertRaisesRegex(RuntimeError, "^rate_limit_exceeded$"):
            self.request_accounts(workspace)
        clock.now += 1
        self.assertEqual(self.request_accounts(workspace).status, "pending")

    def test_f2_agent_flood_cannot_block_approval_or_denial(self):
        workspace = Workspace(clock=Clock(), rate_limit=2)
        approved = self.request_accounts(workspace)
        denied = self.request_accounts(workspace)
        with self.assertRaisesRegex(RuntimeError, "^rate_limit_exceeded$"):
            workspace.check(
                "agt_budget_buddy", "gr_missing", "bank.accounts:read", {}
            )
        grant = workspace.approve(approved.request_id, "sub_x")
        workspace.deny(denied.request_id, "sub_x")
        self.assertEqual(grant.status, "active")
        self.assertEqual(workspace.requests[denied.request_id].status, "denied")

    def test_f2_saturated_rate_and_audit_limits_allow_revocation(self):
        workspace = Workspace(clock=Clock(), rate_limit=1, max_events=3)
        request = self.request_accounts(workspace)
        grant = workspace.approve(request.request_id, "sub_x")
        self.assertEqual(len(workspace.audit.events()), 3)
        with self.assertRaisesRegex(RuntimeError, "^rate_limit_exceeded$"):
            workspace.check(
                "agt_budget_buddy", grant.grant_id, "bank.accounts:read", {}
            )
        connector = workspace.connectors["fake_aggregator"]
        connector.fail_revoke = True
        workspace.revoke(grant.grant_id, actor_id="sub_x")
        self.assertEqual(grant.status, "revoked")
        self.assertTrue(grant.hook_pending)
        connector.fail_revoke = False
        workspace.retry_hook(grant.grant_id)
        self.assertFalse(grant.hook_pending)
        self.assertEqual(connector.status(grant.connection_ref), "revoked")
        self.assertEqual(workspace.audit.verify(), (True, None))

    def test_f2_control_authorization_still_applies_when_rate_limited(self):
        workspace = Workspace(clock=Clock(), rate_limit=1)
        request = self.request_accounts(workspace)
        grant = workspace.approve(request.request_id, "sub_x")
        with self.assertRaisesRegex(ValueError, "^subject_mismatch$"):
            workspace.revoke(grant.grant_id, actor_id="sub_other")
        with self.assertRaisesRegex(ValueError, "^actor_invalid$"):
            workspace.revoke(
                grant.grant_id, actor_type="agent", actor_id="agt_budget_buddy"
            )
        self.assertEqual(grant.status, "active")

        workspace.connectors["fake_aggregator"].fail_revoke = True
        workspace.revoke(grant.grant_id, actor_id="sub_x")
        with self.assertRaisesRegex(ValueError, "^subject_mismatch$"):
            workspace.retry_hook(
                grant.grant_id, actor_type="human", actor_subject_ref="sub_other"
            )
        with self.assertRaisesRegex(ValueError, "^actor_invalid$"):
            workspace.retry_hook(
                grant.grant_id, actor_type="agent", actor_id="agt_budget_buddy"
            )
        self.assertTrue(grant.hook_pending)


if __name__ == "__main__":
    unittest.main()
