SCOPES = {
    "bank.accounts:read": {"target": "bank", "label": "See which accounts exist (names, types)", "limits": []},
    "bank.balances:read": {"target": "bank", "label": "See current balances", "limits": []},
    "bank.transactions:read": {"target": "bank", "label": "Read transactions", "limits": ["max_lookback_days"]},
    "airline.itineraries:read": {"target": "airline", "label": "Read airline itineraries", "limits": []},
    "store.orders:read": {"target": "store", "label": "Read store orders", "limits": []},
}
TARGETS = {
    "bank": {"available": True, "connector": "fake_aggregator"},
    "airline": {"available": False, "reason": "Requires a separately approved provider arrangement"},
    "store": {"available": False, "reason": "Requires a separately approved provider arrangement"},
}
FORBIDDEN_PREFIXES = ("bank.payments", "card.", "payments.")


def classify_scope(scope):
    if any(scope.startswith(prefix) for prefix in FORBIDDEN_PREFIXES):
        return "scope_forbidden", "scope not in catalogue: payments are out of product scope"
    item = SCOPES.get(scope)
    if not item:
        return "scope_unknown", "scope is not in the catalogue"
    target = TARGETS[item["target"]]
    if not target["available"]:
        return "target_unavailable", target["reason"]
    return None, None
