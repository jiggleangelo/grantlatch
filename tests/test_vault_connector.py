import unittest
from grantline import FakeAggregatorConnector, FakeVault


class FakeTests(unittest.TestCase):
    def test_vault_is_write_only(self):
        vault = FakeVault()
        value = "madeup@example.invalid"
        ref = vault.put("email", value)
        self.assertFalse(hasattr(vault, "get"))
        self.assertNotIn(value, repr(vars(vault)))
        self.assertTrue(vault.delete(ref))

    def test_connector(self):
        connector = FakeAggregatorConnector()
        ref = connector.link("sub_x", ("bank.accounts:read",))
        self.assertEqual(connector.status(ref), "linked")
        connector.fail_revoke = True
        self.assertFalse(connector.revoke(ref))
        self.assertEqual(connector.status(ref), "linked")
        connector.fail_revoke = False
        self.assertTrue(connector.revoke(ref))
        self.assertEqual(connector.status(ref), "revoked")


if __name__ == "__main__": unittest.main()
