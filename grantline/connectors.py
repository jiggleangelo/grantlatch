import secrets
from typing import Protocol


class Connector(Protocol):
    name: str
    def link(self, subject_ref: str, scopes: tuple[str, ...]) -> str: ...
    def revoke(self, connection_ref: str) -> bool: ...
    def status(self, connection_ref: str) -> str: ...


class FakeAggregatorConnector:
    name = "fake_aggregator"

    def __init__(self, fail_revoke=False):
        self.fail_revoke = fail_revoke
        self._connections = {}

    def link(self, subject_ref, scopes):
        ref = "conn_" + secrets.token_hex(8)
        self._connections[ref] = "linked"
        return ref

    def revoke(self, connection_ref):
        if self.fail_revoke:
            return False
        if connection_ref not in self._connections:
            return False
        self._connections[connection_ref] = "revoked"
        return True

    def status(self, connection_ref):
        return self._connections.get(connection_ref, "unknown")
