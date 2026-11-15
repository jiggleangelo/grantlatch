import hashlib
import hmac
import secrets
from typing import Protocol


class Vault(Protocol):
    def put(self, kind: str, value: str) -> str: ...
    def delete(self, ref: str) -> bool: ...


class FakeVault:
    """Write-only fake retaining keyed digests, never contact plaintext."""

    def __init__(self, key=None):
        self._key = key or secrets.token_bytes(32)
        self._records = {}

    def put(self, kind, value):
        if not isinstance(value, str) or not 1 <= len(value) <= 254:
            raise ValueError("contact_invalid")
        if any(ord(character) < 32 for character in value):
            raise ValueError("contact_invalid")
        ref = "vlt_" + secrets.token_hex(8)
        digest = hmac.new(
            self._key, (str(kind) + "\0" + value).encode("utf-8"), hashlib.sha256
        ).hexdigest()
        self._records[ref] = (str(kind)[:32], digest)
        return ref

    def delete(self, ref):
        return self._records.pop(ref, None) is not None

    def __repr__(self):
        return f"FakeVault(records={len(self._records)})"
