# grantlatch

Prototype: Scoped grants and audit trails for AI agents: grantlatch

**Use it free, no account:** https://app-grantlatch.manykiln.com/  
**Try the demo (made-up data):** https://try-grantlatch.manykiln.com/  
**Product page:** https://grantlatch.manykiln.com/

> Built and maintained by AI agents at [Manykiln](https://manykiln.com), a studio whose products are written, tested and operated by AI agents. This is a working prototype, not a finished product. No payment is taken anywhere: any checkout, waitlist or payment code in this project runs against fakes only, and the hosted demo uses made-up data.

- Status: prototype; run the 33 automated tests yourself with `python3 -m unittest discover`
- Runs on the Python 3.12 standard library; run the usable app with `python3 app.py` (see below)
- Licence: MIT. Free to use, fork and improve.
- Issues and pull requests are not monitored yet.

---

# grantline MVP

grantline is a local demonstration of scoped agent consent, policy checks, revocation hooks, and an attributed tamper-evident audit chain. All identities are made up. No bank data, credentials, payments, or outbound calls are involved.

## Run

Python 3.12, standard library only:

```sh
python3 demo.py
```

Open http://127.0.0.1:8080. Configure the port with `PORT=9000`. Non-loopback binding requires an explicit `HOST=0.0.0.0` and prints a warning.

```sh
python3 -m unittest discover -s tests
python3 -m unittest tests.test_e2e_demo
```

The end-to-end suite drives the real HTTP handler through in-memory socket fakes and forbids network socket creation. Existing demo tests use loopback HTTP.

## Walkthrough

1. Open the pending Budget Buddy request. Review Sample User A, scopes, purpose, lookback limit, and lifetime, then approve.
2. Open Simulator. Select the transaction grant and try transaction reads with lookbacks of 60 and 365 days, then a payment scope. Observe allow, limit denial, and forbidden-scope denial.
3. Open My agents and revoke. Repeat the formerly allowed action; it is denied as `grant_revoked`.
4. Open Audit. Verify the chain, inspect attribution and decisions, then tamper with a middle event. Verification identifies the first broken sequence.

## SDK

```python
from grantline import Workspace, FakeAggregatorConnector, FakeVault

ws = Workspace(vault=FakeVault(), connectors={
    "fake_aggregator": FakeAggregatorConnector()
})
request = ws.request_grant(
    "agt_budget_buddy", "sub_example", ("bank.transactions:read",),
    {"max_lookback_days": 90}, "Create a monthly summary", 30 * 86400
)
grant = ws.approve(request.request_id, "sub_example")
decision = ws.check(
    "agt_budget_buddy", grant.grant_id,
    "bank.transactions:read", {"lookback_days": 60}
)
ws.revoke(grant.grant_id, actor_subject_ref="sub_example")
```

## Demo authentication

Developer displays random per-session, per-agent tokens. Agent JSON calls send the session cookie and both `Authorization: Bearer …` and `X-Grantline-API: 1`. These modes simulate identity; neither is production authentication.

## Capacity and failure behavior

The original demo keeps bounded in-memory sessions and an HMAC audit chain. Approval and lifecycle operations reserve audit capacity so revocation is not blocked by ordinary agent traffic. The demo remains unchanged and is intentionally separate from the persistent usable app.

## Fakes and limits

The demo's fake connector holds opaque non-redeemable references and cannot fetch data. Its optional fake vault stores keyed digests only. Production use would require real authentication, approved integrations, externally anchored audit storage, and legal review.

## Usable app

`app.py` is the persistent, self-serve grantlatch application. It uses only the Python 3.12 standard library and makes no outbound calls or AI-model calls. Policy decisions are fixed, ordered rules.

Run it with the hosting contract variables:

```sh
APP_HOST=127.0.0.1 \
PORT=8080 \
PUBLIC_BASE_URL=http://127.0.0.1:8080 \
APP_HTTPS_TERMINATED=true \
DATA_DIR=/tmp/grantlatch-data \
APP_DATA_CAP_MB=200 \
python3 app.py
```

In hosted use, `PUBLIC_BASE_URL` should be the platform HTTPS origin and `APP_HOST` may be `0.0.0.0`. The public origin controls Host validation, absolute links, Origin/Referer checks, and form destinations. `GET /healthz` returns `ok`.

The landing page creates a private workspace URL whose random token is its only key. Bookmark it: tokens cannot be recovered. On disk, only the SHA-256 digest of the token appears. Workspaces persist below `DATA_DIR/ws`, use atomic replacement writes, are capped at 5 MB, and can be exported or deleted immediately. Tombstones ensure an in-progress request cannot recreate a deleted workspace.

A workspace supports:

- pasted, uploaded, or form-built scope catalogues for the user's own API;
- `max` and `oneof` grant limits, expiry, consent-screen previews, and immediate local revocation;
- single-action checks and JSONL/CSV batches of up to 2,000 actions;
- partial batch completion with Continue when the wall-clock budget or audit capacity is reached;
- downloadable result CSV files;
- an attributed, plain SHA-256 hash-chained audit trail and complete JSON export;
- a sample workspace with made-up bank examples and a sample-only tamper control.

Payment, card, and money scopes may appear in catalogues so users can see that they were recognized, but grants cannot include them and checks always return `scope_forbidden`. Revocation produces a copyable hook payload and records `hook=not_delivered_copy_payload`; no provider is contacted.

Every page warns against entering real customer personal data, credentials, API keys, or bank, card, and payment-account data. There are no account, contact, payment, analytics, third-party asset, or messaging features.

Storage cleanup runs at startup and daily. It removes untouched workspaces after 24 hours, workspaces idle for 90 days, and tombstones after 30 days. Global admission is capped at 3,000 workspaces and 60 new workspaces per hour. `APP_DATA_CAP_MB` limits all persistent data and causes new writes to fail with an Export-and-Delete suggestion.

Run all tests, including the usable app HTTP suite, with:

```sh
python3 -m unittest discover -s tests
```
