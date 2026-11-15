import dataclasses
import html
import hmac
import json
import os
import secrets
import socket
import sys
import threading
import time
from collections import OrderedDict
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from grantline.catalogue import SCOPES, TARGETS
from grantline.workspace import AGENTS, seeded_workspace

BANNER = "Demo operated by AI agents. Made-up data. Do not enter real personal data. Nothing is charged."
SUBJECT = "sub_demo_user_a"
MAX_BODY = 65536
CAPACITY_MESSAGE = "Audit capacity reached. New requests, approvals and checks are paused. Revocation and one emergency hook retry per grant remain available. Reset starts a new demo and erases this session's history."


def h(value):
    return html.escape(str(value), quote=True)


def normalize_public_base_url(value):
    if not value:
        return None
    value = value.strip()
    parsed = urlsplit(value)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("PUBLIC_BASE_URL must be an HTTP(S) origin without a path, query, credentials, or fragment")
    return f"{parsed.scheme}://{parsed.netloc}"


class Session:
    def __init__(self):
        self.csrf = secrets.token_urlsafe(24)
        self.api_tokens = {agent: secrets.token_urlsafe(32) for agent in AGENTS}
        self.ws = seeded_workspace()
        self.touched = time.time()


class SessionTable:
    def __init__(self, limit=200, idle=1800):
        self.limit, self.idle = limit, idle
        self.lock = threading.Lock()
        self.rows = OrderedDict()

    def get(self, token=None):
        now = time.time()
        with self.lock:
            for key in list(self.rows):
                if now - self.rows[key].touched > self.idle:
                    del self.rows[key]
            created = token not in self.rows
            if created:
                if len(self.rows) >= self.limit:
                    raise RuntimeError("session_capacity_reached")
                token = secrets.token_urlsafe(16)
                self.rows[token] = Session()
            session = self.rows[token]
            session.touched = now
            self.rows.move_to_end(token)
            return token, session, created


SESSIONS = SessionTable()


class BoundedServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, address, handler, max_connections=32, request_timeout=10,
                 secure_cookie=False, allowed_origins=None, public_base_url=None):
        self.slots = threading.BoundedSemaphore(max_connections)
        self.request_timeout = request_timeout
        self.public_base_url = normalize_public_base_url(public_base_url)
        self.secure_cookie = bool(secure_cookie or self.public_base_url)
        super().__init__(address, handler)
        host, port = self.server_address[:2]
        self.allowed_origins = set(allowed_origins or ())
        if self.public_base_url:
            self.allowed_origins.add(self.public_base_url)
        if host in ("127.0.0.1", "localhost"):
            self.allowed_origins.update({f"http://127.0.0.1:{port}", f"http://localhost:{port}"})

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        def deadline():
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        timer = threading.Timer(self.request_timeout, deadline)
        timer.daemon = True
        timer.start()
        try:
            super().process_request_thread(request, client_address)
        finally:
            timer.cancel()
            self.slots.release()


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "grantline-demo"

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, format, *args):
        pass

    def _session(self):
        try:
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            token = cookie["gl_demo"].value if "gl_demo" in cookie else None
        except Exception:
            token = None
        try:
            self.session_token, self.session, self.new_session = SESSIONS.get(token)
            return True
        except RuntimeError:
            self.send_bytes(503, "session_capacity_reached; please try again later")
            return False

    def _cookie(self):
        value = f"gl_demo={self.session_token}; HttpOnly; SameSite=Strict; Path=/"
        if self.server.secure_cookie:
            value += "; Secure"
        return value

    def _absolute_url(self, location):
        public_base_url = getattr(self.server, "public_base_url", None)
        if public_base_url and location.startswith("/"):
            return public_base_url + location
        return location

    def _externalize_html(self, document):
        public_base_url = getattr(self.server, "public_base_url", None)
        if not public_base_url:
            return document
        escaped_base = h(public_base_url)
        return document.replace('href="/', f'href="{escaped_base}/').replace(
            'action="/', f'action="{escaped_base}/'
        )

    def _headers(self, status, content_type, length, location=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        if location is not None:
            self.send_header("Location", self._absolute_url(location))
        if getattr(self, "new_session", False):
            self.send_header("Set-Cookie", self._cookie())
        self.end_headers()
        self.close_connection = True

    def send_bytes(self, status, body, content_type="text/plain; charset=utf-8"):
        body = body if isinstance(body, bytes) else body.encode()
        self._headers(status, content_type, len(body))
        self.wfile.write(body)

    def page(self, title, body, status=200):
        document = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>{h(title)} · grantline</title><link rel="stylesheet" href="/static/style.css"></head><body><div class="banner">{h(BANNER)}</div><nav><a href="/">Start</a><a href="/dev">Developer</a><a href="/grants">My agents</a><a href="/agent">Simulator</a><a href="/audit">Audit</a></nav><main><h1>{h(title)}</h1>{body}</main></body></html>'
        self.send_bytes(status, self._externalize_html(document), "text/html; charset=utf-8")

    def redirect(self, location):
        self._headers(303, "text/plain", 0, location)

    def form(self, action, label, extra=""):
        return f'<form method="post" action="{h(action)}"><input type="hidden" name="csrf" value="{h(self.session.csrf)}">{extra}<button>{h(label)}</button></form>'

    def read_body(self):
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get("Transfer-Encoding") or not lengths:
            self.send_bytes(411, "length_required")
            return None
        try:
            if len(lengths) != 1:
                raise ValueError
            length = int(lengths[0])
            if length < 0:
                raise ValueError
        except ValueError:
            self.send_bytes(400, "content_length_invalid")
            return None
        if length > MAX_BODY:
            self.send_bytes(413, "body_too_large")
            return None
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError
            return raw
        except (OSError, ValueError):
            self.send_bytes(408, "request_timeout")
            return None

    def same_origin(self):
        origin = self.headers.get("Origin")
        return origin is None or origin in self.server.allowed_origins

    def valid_csrf(self, token):
        return isinstance(token, str) and hmac.compare_digest(token.encode(), self.session.csrf.encode())

    def read_form(self):
        if self.headers.get_content_type() != "application/x-www-form-urlencoded":
            self.send_bytes(415, "content_type_unsupported")
            return None
        raw = self.read_body()
        if raw is None:
            return None
        try:
            form = parse_qs(raw.decode(), keep_blank_values=True, strict_parsing=True)
        except (UnicodeDecodeError, ValueError):
            self.send_bytes(400, "form_invalid")
            return None
        if not self.same_origin() or not self.valid_csrf(form.get("csrf", [""])[0]):
            self.send_bytes(403, "csrf_invalid")
            return None
        return {key: values[0] for key, values in form.items()}

    def read_json(self):
        if self.headers.get_content_type() != "application/json":
            self.send_bytes(415, "content_type_unsupported")
            return None
        raw = self.read_body()
        if raw is None:
            return None
        try:
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError
            return value
        except (UnicodeDecodeError, ValueError):
            self.send_bytes(400, "json_invalid")
            return None

    def json_response(self, status, value):
        self.send_bytes(status, json.dumps(value, separators=(",", ":")), "application/json; charset=utf-8")

    def api_actor(self, data):
        if not self.same_origin():
            self.json_response(403, {"error": "origin_rejected"})
            return None
        authorization = self.headers.get("Authorization")
        api_header = self.headers.get("X-Grantline-API")
        if authorization is not None or api_header is not None:
            if api_header != "1":
                self.json_response(403, {"error": "api_header_required"})
                return None
            supplied = authorization[7:] if authorization and authorization.startswith("Bearer ") else ""
            actor = next((agent for agent, token in self.session.api_tokens.items()
                          if hmac.compare_digest(supplied.encode(), token.encode())), None)
            if actor is None:
                self.json_response(401, {"error": "api_auth_required"})
                return None
        else:
            if not self.valid_csrf(self.headers.get("X-CSRF-Token", "")):
                self.json_response(403, {"error": "csrf_invalid"})
                return None
            actor = data.get("agent_id")
            if not isinstance(actor, str) or actor not in AGENTS:
                self.json_response(403, {"error": "agent_unknown"})
                return None
        if data.get("agent_id", actor) != actor:
            self.json_response(403, {"error": "agent_mismatch"})
            return None
        return actor

    def rejected(self, error, api=False):
        code = str(error)
        if code == "audit_capacity_reached":
            status, detail = 409, CAPACITY_MESSAGE
        elif code == "rate_limit_exceeded":
            status, detail = 429, "Agent rate limit reached. Try again after the rate window."
        else:
            status, code, detail = 400, "request_rejected", "The request was invalid or is no longer available."
        if api:
            self.json_response(status, {"error": code, "detail": detail})
        else:
            self.page("Request paused" if status != 400 else "Request rejected",
                      f'<p>{h(detail)}</p><p><a href="/audit">View audit</a></p>', status)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/healthz":
            self.send_bytes(200, "ok")
            return
        if path == "/static/style.css":
            try:
                with open(os.path.join(os.path.dirname(__file__), "static", "style.css"), "rb") as source:
                    self.send_bytes(200, source.read(), "text/css; charset=utf-8")
            except OSError:
                self.send_bytes(404, "not_found")
            return
        if not self._session():
            return
        routes = {"/": self.home, "/dev": self.dev, "/grants": self.grants_page,
                  "/agent": self.agent, "/audit": self.audit_page}
        if path in routes:
            routes[path]()
        elif path.startswith("/consent/"):
            self.consent(path.split("/", 2)[2])
        elif path == "/api/v1/audit":
            audit = self.session.ws.audit
            ok, bad = audit.verify()
            self.json_response(200, {"events": audit.events(SUBJECT), "chain_ok": ok,
                                    "first_bad_seq": bad, "head_hash": audit.head_hash,
                                    "event_count": audit.event_count,
                                    "remaining_events": audit.remaining})
        else:
            self.page("Not found", "<p>Unknown route.</p>", 404)

    def do_POST(self):
        if not self._session():
            return
        path = urlsplit(self.path).path
        ws = self.session.ws
        if path in ("/api/v1/grant-requests", "/api/v1/check"):
            data = self.read_json()
            if data is None:
                return
            actor = self.api_actor(data)
            if actor is None:
                return
            try:
                if path.endswith("grant-requests"):
                    if data.get("subject_ref") != SUBJECT:
                        self.json_response(403, {"error": "subject_rejected"})
                        return
                    result = ws.request_grant(actor, SUBJECT, data["scopes"], data.get("limits", {}), data["purpose"], data["ttl_seconds"])
                    self.json_response(201, dataclasses.asdict(result))
                else:
                    result = ws.check(actor, data.get("grant_id"), data.get("scope"), data.get("params", {}))
                    self.json_response(200, dataclasses.asdict(result))
            except (KeyError, TypeError, ValueError, RuntimeError) as error:
                self.rejected(error, api=True)
            return
        form = self.read_form()
        if form is None:
            return
        try:
            if path == "/reset":
                self.session.ws = seeded_workspace()
                self.redirect("/")
            elif path == "/dev/requests":
                scopes = [scope for scope in SCOPES if form.get("scope_" + scope) == "on"]
                limits = {"max_lookback_days": int(form.get("lookback", "0"))} if "bank.transactions:read" in scopes else {}
                request = ws.request_grant(form.get("agent_id"), SUBJECT, scopes, limits,
                                           form.get("purpose", ""), int(form.get("ttl_days", "0")) * 86400)
                self.redirect("/consent/" + request.request_id)
            elif path.startswith("/consent/"):
                _, request_id, action = path.strip("/").split("/")
                if action == "approve":
                    grant = ws.approve(request_id, SUBJECT, form.get("contact") or None)
                    self.redirect("/grants#" + grant.grant_id)
                elif action == "deny":
                    ws.deny(request_id, SUBJECT)
                    self.redirect("/grants")
                else:
                    raise ValueError("action_invalid")
            elif path.startswith("/grants/"):
                _, grant_id, action = path.strip("/").split("/")
                if action == "revoke":
                    ws.revoke(grant_id, actor_subject_ref=SUBJECT)
                elif action == "retry":
                    ws.retry_hook(grant_id, actor_type="human", actor_subject_ref=SUBJECT)
                else:
                    raise ValueError("action_invalid")
                self.redirect("/grants#" + grant_id)
            elif path == "/agent/check":
                params = {"lookback_days": int(form["lookback"])} if form.get("lookback") else {}
                decision = ws.check(form.get("agent_id"), form.get("grant_id"), form.get("scope"), params)
                label = "ALLOW" if decision.allow else "DENY"
                self.page("Policy decision", f'<section><strong>{label}</strong><p>{h(decision.reason)}: {h(decision.detail)}</p></section><a href="/agent">Try another</a>')
            elif path == "/connector/failure":
                ws.connectors["fake_aggregator"].fail_revoke = form.get("enabled") == "on"
                self.redirect("/dev")
            elif path == "/audit/tamper":
                with ws.audit._lock:
                    events = ws.audit._events
                    if events:
                        events[len(events) // 2]["data"]["demo_tampered"] = True
                self.redirect("/audit")
            else:
                self.page("Not found", "<p>Unknown route.</p>", 404)
        except (KeyError, IndexError, TypeError, ValueError, RuntimeError) as error:
            self.rejected(error)

    def home(self):
        body = '<section><p>Review a made-up consent request, simulate actions, revoke, then verify the audit chain. No outbound requests or bank data.</p></section>'
        for request in self.session.ws.requests.values():
            if request.status == "pending" and request.subject_ref == SUBJECT:
                body += f'<section><h2>{h(AGENTS[request.agent_id]["name"])}</h2><p>{h(request.purpose)}</p><a href="/consent/{h(request.request_id)}">Review consent</a></section>'
        self.page("Scoped consent demo", body + self.form("/reset", "Reset demo"))

    def dev(self):
        agents = ''.join(f'<option value="{h(agent)}">{h(item["name"])}</option>' for agent, item in AGENTS.items())
        scopes = ""
        for scope, item in SCOPES.items():
            target = TARGETS[item["target"]]
            disabled = " disabled" if not target["available"] else ""
            note = "available" if target["available"] else target["reason"]
            scopes += f'<label><input type="checkbox" name="scope_{h(scope)}"{disabled}> {h(item["label"])} — {h(note)}</label>'
        extra = f'<label>Agent<select name="agent_id">{agents}</select></label>{scopes}<label>Transaction lookback limit (days)<input name="lookback" type="number" min="0" max="3650" value="90"></label><label>Grant lifetime (days)<input name="ttl_days" type="number" min="1" max="90" value="30"></label><label>Purpose (do not include personal data)<textarea name="purpose" maxlength="200" required>Create a made-up summary</textarea></label>'
        checked = " checked" if self.session.ws.connectors["fake_aggregator"].fail_revoke else ""
        toggle = f'<label><input type="checkbox" name="enabled"{checked}> Simulate connector revoke failure</label>'
        tokens = ''.join(f'<li>{h(agent)}: <code>{h(token)}</code></li>' for agent, token in self.session.api_tokens.items())
        body = self.form("/dev/requests", "Create consent request", extra)
        body += self.form("/connector/failure", "Save connector setting", toggle)
        body += f'<section><h2>Session API tokens</h2><p>Agent API: Authorization: Bearer … and X-Grantline-API: 1. Browser simulator: session cookie and X-CSRF-Token. These are local simulated identities.</p><ul>{tokens}</ul></section>'
        self.page("Developer", body)

    def consent(self, request_id):
        request = self.session.ws.requests.get(request_id)
        if not request or request.subject_ref != SUBJECT:
            self.page("Not found", "<p>Consent request not found.</p>", 404)
            return
        scopes = ''.join(f'<li>{h(SCOPES[scope]["label"])} — <code>{h(scope)}</code></li>' for scope in request.scopes)
        limits = ''.join(f'<li>{h(key)}: {h(value)}</li>' for key, value in request.limits.items()) or '<li>None</li>'
        body = f'<section><p>Sample User A</p><p><strong>{h(AGENTS[request.agent_id]["name"])}</strong> asks for:</p><ul>{scopes}</ul><p>Purpose: {h(request.purpose)}</p><p>Limits:</p><ul>{limits}</ul><p>Grant expires {h(request.ttl_seconds / 86400):s} days after approval ({h(request.ttl_seconds)} seconds).</p><p>Status: {h(request.status)}</p></section>'
        if request.status == "pending":
            body += self.form(f"/consent/{request.request_id}/approve", "Approve", '<label>Optional revocation notice contact — enter a made-up address only<input name="contact" maxlength="254" autocomplete="off"></label>')
            body += self.form(f"/consent/{request.request_id}/deny", "Deny")
        self.page("Review consent", body)

    def grants_page(self):
        body = ""
        for grant in self.session.ws.list_grants(SUBJECT):
            body += f'<section id="{h(grant.grant_id)}"><h2>{h(AGENTS[grant.agent_id]["name"])}</h2><p><code>{h(grant.grant_id)}</code></p><p>{h(", ".join(grant.scopes))}</p><p>Purpose: {h(grant.purpose)}</p><p>Expires at Unix time {h(grant.expires_at)}</p><p>Status: <strong>{h(grant.status)}</strong></p>'
            if grant.status == "active":
                body += self.form(f"/grants/{grant.grant_id}/revoke", "Revoke")
            if grant.status == "revoked" and grant.hook_pending:
                body += '<p class="warn">Revoked here; provider confirmation pending.</p>'
                body += self.form(f"/grants/{grant.grant_id}/retry", "Retry hook")
            body += '</section>'
        self.page("My agents", body or '<p>No grants.</p>')

    def agent(self):
        options = ''.join(f'<option value="{h(grant.grant_id)}">{h(grant.grant_id)} — {h(grant.status)}</option>' for grant in self.session.ws.list_grants(SUBJECT))
        agents = ''.join(f'<option value="{h(agent)}">{h(item["name"])}</option>' for agent, item in AGENTS.items())
        scopes = ''.join(f'<option value="{h(scope)}">{h(scope)}</option>' for scope in list(SCOPES) + ["bank.payments:initiate"])
        extra = f'<label>Agent<select name="agent_id">{agents}</select></label><label>Grant<select name="grant_id">{options}</select></label><label>Scope<select name="scope">{scopes}</select></label><label>Lookback days<input type="number" name="lookback" min="0" max="3650" value="60"></label>'
        self.page("Agent simulator", self.form("/agent/check", "Check policy", extra))

    def audit_page(self):
        audit = self.session.ws.audit
        ok, bad = audit.verify()
        status = "Chain verifies" if ok else f"Chain broken at sequence {bad}"
        body = f'<section><p>{h(status)}</p><p>Published in-memory head: <code>{h(audit.head_hash)}</code> ({audit.event_count} events)</p><p>Ordinary event slots remaining: {audit.remaining}. Lifecycle events have reserved capacity.</p><p>This HMAC chain is in memory, without durable external anchoring.</p><a href="/audit">Verify chain</a></section>'
        if audit.remaining < 2:
            body += f'<p class="warn">{h(CAPACITY_MESSAGE)} Approval requires two ordinary event slots.</p>'
        rows = ""
        for event in audit.events(SUBJECT):
            rows += f'<tr><td>{event["seq"]}</td><td>{h(event["event"])}</td><td>{h(event["actor_type"])}</td><td>{h(event["actor_id"])}</td><td>{h(event["subject_ref"])}</td><td><code>{h(json.dumps(event["data"]))}</code></td><td><code>{h(event["prev_hash"])}</code></td><td><code>{h(event["hash"])}</code></td></tr>'
        body += '<table><thead><tr><th>Seq</th><th>Event</th><th>Actor type</th><th>Actor</th><th>Subject</th><th>Decision / details</th><th>Previous hash</th><th>Hash</th></tr></thead><tbody>' + rows + '</tbody></table>'
        body += self.form("/audit/tamper", "Tamper with middle event (demo)")
        body += self.form("/reset", "Reset demo (erase this history)")
        self.page("Audit", body)


def make_server(host="127.0.0.1", port=8080, *, max_connections=32,
                request_timeout=10, secure_cookie=False, allowed_origins=None,
                public_base_url=None):
    return BoundedServer((host, int(port)), DemoHandler, max_connections,
                         request_timeout, secure_cookie, allowed_origins,
                         public_base_url)


def main():
    host = os.environ.get("DEMO_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8080"))
    public_base_url = normalize_public_base_url(os.environ.get("PUBLIC_BASE_URL"))
    origins = [value.strip() for value in os.environ.get("ALLOWED_ORIGINS", "").split(",") if value.strip()]
    if public_base_url:
        origins.append(public_base_url)
    if host not in ("127.0.0.1", "localhost"):
        print("WARNING: this local demo uses in-memory simulated authentication.", file=sys.stderr)
    server = make_server(
        host,
        port,
        secure_cookie=os.environ.get("SECURE_COOKIE") == "1" or bool(public_base_url),
        allowed_origins=origins,
        public_base_url=public_base_url,
    )
    display_base = public_base_url or f"http://{host}:{server.server_port}"
    print(f"grantline demo listening on {display_base}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
