import csv
import html
import io
import json
import os
import re
import socket
import threading
import time
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from grantline.store import (MAX_AUDIT, CAPACITY_MESSAGE, StoreError, WorkspaceStore,
    append_event, audit_remaining, canonical, iso_time, parse_time, validate_catalogue, verify_chain)

NOTICE = ('Operated by AI agents. Early version: keep your own copy of anything important. '
          'Do not enter real customer personal data, credentials or API keys, or bank, card or payment account data. Nothing is charged.')
MAX_BODY = 1024 * 1024
BOOKMARK = ('Bookmark this link: it is the only key and cannot be recovered. '
            'Workspaces with no saved changes, including sample workspaces, are deleted after 24 hours; viewing does not extend this. '
            'After a saved change, deletion occurs after 90 days without another saved change.')


def h(value):
    return html.escape(str(value), quote=True)


def normalize_base(value):
    parsed = urlsplit(value)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc or parsed.path not in ('', '/') or parsed.query or parsed.fragment or parsed.username is not None:
        raise ValueError('PUBLIC_BASE_URL must be an HTTP(S) origin')
    return f'{parsed.scheme}://{parsed.netloc}'


def json_value(text, label='JSON'):
    try:
        return json.loads(text.lstrip('\ufeff'), parse_constant=lambda value: (_ for _ in ()).throw(ValueError('non-finite number')))
    except json.JSONDecodeError as error:
        raise StoreError(f'{label}: line {error.lineno}, column {error.colno}: invalid JSON')
    except (ValueError, RecursionError):
        raise StoreError(f'{label}: invalid JSON or numeric/nesting limit exceeded')


def csv_cell(value):
    text = '' if value is None else str(value)
    # Also protect leading whitespace/control characters accepted by spreadsheets.
    if text.lstrip().startswith(('=', '+', '-', '@')) or text.startswith(('\t', '\r', '\n')):
        return "'" + text
    return text


class AppServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, address, handler, store, public_base_url, max_connections=32,
                 request_timeout=10, monotonic=time.monotonic, batch_seconds=4):
        self.store = store
        self.public_base_url = normalize_base(public_base_url)
        self.public = urlsplit(self.public_base_url)
        self.slots = threading.BoundedSemaphore(max_connections)
        self.request_timeout = request_timeout
        self.monotonic = monotonic
        self.batch_seconds = batch_seconds
        super().__init__(address, handler)

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
        def stop():
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        timer = threading.Timer(self.request_timeout, stop)
        timer.daemon = True
        timer.start()
        try:
            super().process_request_thread(request, client_address)
        finally:
            # Socket deadlines never release a worker slot. The handler must exit.
            timer.cancel()
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = 'grantlatch'

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, format, *args):
        pass

    def send_data(self, status, body, content_type='text/plain; charset=utf-8', location=None, workspace=False, disposition=None):
        body = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        for name, value in {
            'Content-Type': content_type, 'Content-Length': str(len(body)),
            'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
            'Referrer-Policy': 'same-origin', 'X-Content-Type-Options': 'nosniff',
            'Cache-Control': 'no-store' if workspace else 'no-cache', 'Connection': 'close'
        }.items():
            self.send_header(name, value)
        if location:
            self.send_header('Location', self.url(location))
        if disposition:
            self.send_header('Content-Disposition', disposition)
        self.end_headers()
        self.close_connection = True
        self.wfile.write(body)

    def url(self, path):
        return self.server.public_base_url + path if path.startswith('/') else path

    def page(self, title, content, status=200, token=None, banner=None):
        nav = f'<a href="{h(self.url("/"))}">grantlatch</a>'
        permanent = ''
        if token:
            root = '/w/' + token
            nav += ''.join(f'<a href="{h(self.url(root + suffix))}">{label}</a>' for suffix, label in (
                ('', 'Dashboard'), ('/catalogue', 'Catalogue'), ('/grants', 'Grants'),
                ('/check', 'Check'), ('/batch', 'Batch'), ('/audit', 'Audit')))
            permanent = f'<a href="{h(self.url(root + "/export"))}">Export everything</a>' + self.form_html(root + '/delete', 'Delete this workspace now')
        notice = f'<div class="notice">{h(NOTICE)} <a href="https://manykiln.com/privacy">Privacy</a><br>Decisions come from fixed rules, not AI.</div>'
        banner_html = f'<p class="bookmark">{h(banner)}</p>' if banner else ''
        document = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>{h(title)} · grantlatch</title><link rel="stylesheet" href="{h(self.url("/static/style.css"))}"><style>.notice,.bookmark,.error{{padding:1rem;background:#fff0b8}}nav{{display:flex;gap:1rem;flex-wrap:wrap}}textarea{{min-height:8rem}}td{{vertical-align:top}}.forbidden{{color:#a11919}}</style></head><body>{notice}<nav>{nav}</nav><main>{banner_html}<h1>{h(title)}</h1>{content}<hr>{permanent}</main></body></html>'
        self.send_data(status, document, 'text/html; charset=utf-8', workspace=bool(token))

    def form_html(self, path, button, fields='', multipart=False):
        encoding = ' enctype="multipart/form-data"' if multipart else ''
        return f'<form method="post" action="{h(self.url(path))}"{encoding}>{fields}<button>{h(button)}</button></form>'

    def error_page(self, status, message, token=None):
        self.page('Request could not be completed', f'<p class="error">{h(message)}</p>', status, token)

    def redirect(self, path):
        self.send_data(303, b'', location=path, workspace=path.startswith('/w/'))

    def valid_host(self):
        return self.headers.get('Host', '') == self.server.public.netloc

    def valid_post_origin(self):
        origin = self.headers.get('Origin')
        if origin is not None:
            return origin == self.server.public_base_url
        referer = self.headers.get('Referer', '')
        return referer == self.server.public_base_url or referer.startswith(self.server.public_base_url + '/')

    def read_body(self):
        lengths = self.headers.get_all('Content-Length', [])
        if self.headers.get('Transfer-Encoding') or len(lengths) != 1:
            raise StoreError('length_required')
        try:
            length = int(lengths[0])
        except ValueError:
            raise StoreError('content_length_invalid')
        if length < 0:
            raise StoreError('content_length_invalid')
        multipart = self.headers.get_content_type() == 'multipart/form-data'
        limit = MAX_BODY + 65536 if multipart else MAX_BODY
        if not multipart and urlsplit(self.path).path.endswith(('/batch', '/catalogue')):
            limit = MAX_BODY * 3 + 65536
        if length > limit:
            raise StoreError('body_too_large')
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise StoreError('request_timeout')
        return raw

    def form(self):
        raw = self.read_body()
        content_type = self.headers.get('Content-Type', '')
        if content_type.startswith('application/x-www-form-urlencoded'):
            try:
                result = parse_qs(raw.decode('utf-8-sig'), keep_blank_values=True, errors='strict', max_num_fields=3000)
            except (UnicodeDecodeError, ValueError):
                raise StoreError('form_invalid: use UTF-8 text')
        elif content_type.startswith('multipart/form-data'):
            message = BytesParser(policy=default).parsebytes(('Content-Type: ' + content_type + '\r\nMIME-Version: 1.0\r\n\r\n').encode() + raw)
            if not message.is_multipart() or message.defects:
                raise StoreError('multipart form is invalid')
            result = {}
            for part in message.iter_parts():
                name = part.get_param('name', header='content-disposition')
                if not name:
                    continue
                payload = part.get_payload(decode=True) or b''
                if len(payload) > MAX_BODY:
                    raise StoreError('body_too_large')
                try:
                    item = payload.decode('utf-8-sig')
                except UnicodeDecodeError:
                    raise StoreError('Upload must use UTF-8 encoding; save the file as UTF-8 and try again.')
                result.setdefault(name, []).append(item)
                if part.get_filename():
                    result.setdefault(name + '_filename', []).append(part.get_filename())
        else:
            raise StoreError('content_type_unsupported')
        for values in result.values():
            if any(len(value.encode()) > MAX_BODY for value in values):
                raise StoreError('body_too_large')
        return result

    @staticmethod
    def one(form, name, default=''):
        return form.get(name, [default])[0]

    def workspace(self, token):
        return self.server.store.load(token)

    def do_GET(self):
        if not self.valid_host():
            self.error_page(400, 'host_rejected')
            return
        path = urlsplit(self.path).path
        try:
            if path == '/healthz':
                self.send_data(200, 'ok')
            elif path == '/static/style.css':
                try:
                    with open(os.path.join(os.path.dirname(__file__), 'static', 'style.css'), 'rb') as source:
                        self.send_data(200, source.read(), 'text/css; charset=utf-8')
                except OSError:
                    self.send_data(404, 'not_found')
            elif path == '/':
                self.home()
            else:
                self.workspace_get(path)
        except StoreError as error:
            self.error_page(404 if str(error) == 'workspace_not_found' else 409, str(error))
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self.error_page(500, 'The request could not be completed.')

    def do_POST(self):
        if not self.valid_host():
            self.error_page(400, 'host_rejected')
            return
        if not self.valid_post_origin():
            self.error_page(403, 'origin_rejected')
            return
        path = urlsplit(self.path).path
        try:
            if path == '/w':
                form = self.form()
                # Use the socket peer, never an untrusted forwarded header.
                token = self.server.store.create(self.one(form, 'sample') == '1', client_ip=self.client_address[0])
                self.redirect('/w/' + token + '?created=1')
            else:
                self.workspace_post(path)
        except StoreError as error:
            text = str(error)
            status = 413 if text == 'body_too_large' else 429 if '_rate_' in text else 404 if text == 'workspace_not_found' else 409 if text == CAPACITY_MESSAGE else 400
            match = re.match(r'/w/([A-Za-z0-9_-]+)', path)
            self.error_page(status, text, match.group(1) if match else None)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self.error_page(500, 'The request could not be completed.')

    def home(self):
        content = '<p>Define a scope catalogue for your API, issue limited grants, and replay agent action logs through deterministic policy rules. No outbound calls are made.</p>'
        content += self.form_html('/w', 'Start a workspace')
        content += self.form_html('/w', 'Try with sample data', '<input type="hidden" name="sample" value="1">')
        self.page('Scoped grants and audit trails', content)

    def split_workspace_path(self, path):
        match = re.fullmatch(r'/w/([A-Za-z0-9_-]+)(/.*)?', path)
        if not match:
            raise StoreError('workspace_not_found')
        return match.group(1), match.group(2) or ''

    def workspace_get(self, path):
        token, suffix = self.split_workspace_path(path)
        state = self.workspace(token)
        routes = {'': self.dashboard, '/catalogue': self.catalogue_page, '/grants': self.grants_page,
                  '/check': self.check_page, '/batch': self.batch_page, '/audit': self.audit_page, '/export': self.export}
        if suffix in routes:
            routes[suffix](token, state)
        elif re.fullmatch(r'/grants/gr_[0-9a-f]+', suffix):
            self.grant_page(token, state, suffix.rsplit('/', 1)[1])
        elif suffix == '/batch/results.csv':
            self.results_csv(state)
        else:
            self.error_page(404, 'not_found', token)

    def workspace_post(self, path):
        token, suffix = self.split_workspace_path(path)
        with self.server.store.lock_for(self.server.store.key(token)):
            state = self.workspace(token)
            form = self.form()
            if suffix == '/delete':
                self.server.store.delete(token)
                self.page('Workspace deleted', '<p>The workspace files were removed immediately. This URL cannot be recreated.</p>')
            elif suffix == '/catalogue':
                self.update_catalogue(token, state, form)
            elif suffix == '/grants':
                self.issue(token, state, form)
            elif re.fullmatch(r'/grants/gr_[0-9a-f]+/revoke', suffix):
                payload = self.server.store.revoke(state, suffix.split('/')[2])
                self.server.store.save(token, state)
                self.page('Grant revoked', f'<p>Revocation takes effect on the next check. The app made no outbound call.</p><textarea readonly>{h(json.dumps(payload, indent=2))}</textarea>', token=token)
            elif suffix == '/check':
                self.single_check(token, state, form)
            elif suffix == '/batch':
                self.run_batch(token, state, form)
            elif suffix == '/audit/tamper' and state.get('sample'):
                if state['audit']:
                    state['audit'][len(state['audit']) // 2]['data']['sample_tampered'] = True
                    self.server.store.save(token, state)
                self.redirect(f'/w/{token}/audit')
            else:
                self.error_page(404, 'not_found', token)

    def dashboard(self, token, state):
        ok, bad = verify_chain(state['audit'])
        active = sum(self.grant_status(g) == 'active' for g in state['grants'].values())
        content = f'<p>{len(state["catalogue"]["scopes"])} catalogue scopes; {len(state["grants"])} grants ({active} active).</p><p>Last batch: {h(json.dumps(state.get("last_batch_counts", {})))}</p><p>Audit: {"verifies" if ok else "broken at sequence " + str(bad)}; {len(state["audit"])} events.</p>'
        if audit_remaining(state) < 2:
            content += f'<p class="error">{h(CAPACITY_MESSAGE)}</p>'
        self.page('Workspace dashboard', content, token=token, banner=BOOKMARK)

    def catalogue_page(self, token, state, message=''):
        affected = state.get('catalogue_affected_grants', [])
        if affected:
            message += '<p class="error">Catalogue replacement affected active grants. Changed rules require new consent; missing limits are denied. Review and reissue these grants: ' + h(', '.join(affected)) + '</p>'
        rows = ''.join(f'<tr><td>{h(name)}</td><td>{h(item["label"])}</td><td>{h(json.dumps(item["limits"]))}</td><td>{"Always forbidden" if item.get("forbidden") else ""}</td></tr>' for name, item in state['catalogue']['scopes'].items())
        fields = '<p>Replacing scope rules can affect active grants. Existing consent definitions are retained in grant previews.</p><label>Paste catalogue JSON<textarea name="catalogue"></textarea></label><label>Or upload JSON (up to 1 MB)<input type="file" name="file" accept="application/json"></label>'
        content = message + self.form_html('/w/' + token + '/catalogue', 'Replace catalogue', fields, True)
        fields = '<h2>Add one scope</h2><label>Scope name<input name="scope"></label><label>Plain-language label<input name="label" maxlength="120"></label><label>Limit name (optional)<input name="limit_name"></label><label>Limit type<select name="limit_type"><option>max</option><option>oneof</option></select></label><label>Parameter name<input name="param"></label>'
        content += self.form_html('/w/' + token + '/catalogue', 'Add scope', fields)
        self.page('Scope catalogue', content + '<table><tr><th>Scope</th><th>Label</th><th>Rules</th><th>Status</th></tr>' + rows + '</table>', token=token)

    def update_catalogue(self, token, state, form):
        text = self.one(form, 'catalogue').strip() or self.one(form, 'file').strip()
        if text:
            value = json_value(text, 'Catalogue')
        else:
            value = {'scopes': {name: {'label': item['label'], 'limits': item['limits']} for name, item in state['catalogue']['scopes'].items()}}
            rules = {}
            if self.one(form, 'limit_name'):
                rules[self.one(form, 'limit_name')] = {'type': self.one(form, 'limit_type'), 'param': self.one(form, 'param')}
            value['scopes'][self.one(form, 'scope')] = {'label': self.one(form, 'label'), 'limits': rules}
        self.server.store.update_catalogue(state, value)
        self.server.store.save(token, state)
        self.redirect(f'/w/{token}/catalogue')

    def grants_page(self, token, state):
        fields = '<label>Agent id<input name="agent_id" pattern="agt_[A-Za-z0-9_]{1,64}" required></label><label>Pseudonymous subject ref<input name="subject_ref" pattern="sub_[A-Za-z0-9_]{1,64}" required></label>'
        for scope, item in state['catalogue']['scopes'].items():
            disabled = ' disabled' if item.get('forbidden') else ''
            fields += f'<fieldset><legend>{h(item["label"])}</legend><label><input type="checkbox" name="scopes" value="{h(scope)}"{disabled}> {h(scope)}</label>'
            if not disabled:
                for name, rule in item['limits'].items():
                    field = h('limit:' + scope + ':' + name)
                    label = h(name.replace('_', ' ') + ' (' + rule['param'] + ')')
                    if rule['type'] == 'max':
                        fields += f'<label>{label}: maximum integer<input type="number" name="{field}" min="0" max="1000000000" step="1"></label>'
                    else:
                        fields += f'<label>{label}: allowed values, one per line (up to 20)<textarea name="{field}"></textarea></label>'
            fields += '</fieldset>'
        fields += '<label>Purpose<input name="purpose" maxlength="200" required></label><label>Lifetime in minutes (1 to 129600)<input type="number" name="minutes" min="1" max="129600" value="60"></label>'
        rows = ''.join(f'<tr><td><a href="{h(self.url("/w/" + token + "/grants/" + gid))}">{h(gid)}</a></td><td>{h(g["agent_id"])}</td><td>{h(self.grant_status(g))}</td></tr>' for gid, g in state['grants'].items())
        self.page('Grants', self.form_html('/w/' + token + '/grants', 'Issue grant', fields) + '<table><tr><th>Grant</th><th>Agent</th><th>Status</th></tr>' + rows + '</table>', token=token)

    def issue(self, token, state, form):
        try:
            minutes = int(self.one(form, 'minutes'))
        except ValueError:
            raise StoreError('lifetime is invalid')
        scopes = form.get('scopes', [])
        if 'limits' in form:
            # Preserve compatibility for existing form clients.
            limits = json_value(self.one(form, 'limits'), 'Limits')
        else:
            limits = {}
            for scope in scopes:
                item = state['catalogue']['scopes'].get(scope)
                if item is None:
                    raise StoreError('scope_unknown')
                for name, rule in item['limits'].items():
                    raw = self.one(form, 'limit:' + scope + ':' + name)
                    try:
                        value = int(raw) if rule['type'] == 'max' else raw.splitlines()
                    except ValueError:
                        raise StoreError(f'limit {name} requires an integer')
                    if name in limits and limits[name] != value:
                        raise StoreError(f'limit {name} must have the same value for all selected scopes')
                    limits[name] = value
        grant = self.server.store.issue_grant(state, self.one(form, 'agent_id'), self.one(form, 'subject_ref'), scopes, limits, self.one(form, 'purpose'), minutes * 60)
        self.server.store.save(token, state)
        self.redirect(f'/w/{token}/grants/{grant["grant_id"]}')

    def grant_status(self, grant):
        if grant.get('revoked_at') is not None:
            return 'revoked'
        return 'expired' if self.server.store.clock() >= grant['expires_at'] else 'active'

    def grant_page(self, token, state, grant_id):
        grant = state['grants'].get(grant_id)
        if not grant:
            self.error_page(404, 'grant_not_found', token)
            return
        definitions = grant.get('scope_definitions', state['catalogue']['scopes'])
        scopes = ''
        for scope in grant['scopes']:
            item = definitions.get(scope, {'label': scope, 'limits': {}})
            scopes += f'<li>{h(item["label"])} — <code>{h(scope)}</code><ul>'
            for name, rule in item['limits'].items():
                value = grant['limits'].get(name)
                description = f'{rule["param"]} must be at most {value}' if rule['type'] == 'max' else f'{rule["param"]} must be one of: ' + (', '.join(value) if isinstance(value, list) and value else '(no values allowed)')
                scopes += f'<li>{h(name.replace("_", " "))}: {h(description)}</li>'
            scopes += '</ul></li>'
        content = f'<p>Agent: {h(grant["agent_id"])}</p><p>Subject: {h(grant["subject_ref"])}</p><ul>{scopes}</ul><p>Purpose: {h(grant["purpose"])}</p><p>Expires: {h(iso_time(grant["expires_at"]))}</p><p>Status: <strong>{h(self.grant_status(grant))}</strong></p>'
        if grant.get('revoked_at') is None:
            content += self.form_html('/w/' + token + '/grants/' + grant_id + '/revoke', 'Revoke')
        self.page('Consent-screen preview', content, token=token)

    def check_page(self, token, state, result=None):
        output = '' if result is None else f'<h2>{h(result["decision"])}</h2><p><code>{h(result["reason"])}</code>: {h(result["detail"])}</p>'
        sample = {'agent_id': 'agt_example', 'grant_id': 'gr_...', 'scope': 'crm.contacts:read', 'params': {'records': 50}}
        fields = f'<label>Action JSON<textarea name="action">{h(json.dumps(sample, indent=2))}</textarea></label>'
        self.page('Check one action', output + self.form_html('/w/' + token + '/check', 'Check action', fields), token=token)

    def single_check(self, token, state, form):
        action = json_value(self.one(form, 'action'), 'Action')
        result = self.server.store.check(state, action)
        self.server.store.save(token, state)
        self.check_page(token, state, result)

    def parse_batch(self, text, filename, format_name):
        if len(text.encode()) > MAX_BODY:
            raise StoreError('body_too_large')
        text = text.lstrip('\ufeff')
        actions = []

        def add(action, line):
            if not isinstance(action, dict):
                raise StoreError(f'line {line}: action must be an object')
            try:
                parse_time(action.get('at'), 0)
                canonical(action)
            except (StoreError, ValueError, TypeError, RecursionError) as error:
                raise StoreError(f'line {line}: {error}')
            action['_line'] = line
            actions.append(action)
            if len(actions) > 2000:
                raise StoreError('a batch may contain at most 2000 actions')

        if filename.lower().endswith('.csv') or format_name == 'csv':
            reader = csv.DictReader(io.StringIO(text, newline=''), strict=True)
            try:
                if not reader.fieldnames or not {'agent_id', 'grant_id', 'scope', 'params'}.issubset(reader.fieldnames):
                    raise StoreError('CSV columns must include agent_id, grant_id, scope and params')
                while True:
                    line = reader.line_num + 1
                    row = next(reader, None)
                    if row is None:
                        break
                    if None in row or any(row.get(k) is None for k in ('agent_id', 'grant_id', 'scope', 'params')):
                        raise StoreError(f'line {line}: CSV column count is invalid')
                    params = json_value(row['params'] or '{}', f'line {line}: params')
                    add({'agent_id': row['agent_id'], 'grant_id': row['grant_id'], 'scope': row['scope'],
                         'params': params, 'at': row.get('at') or None}, line)
            except csv.Error as error:
                raise StoreError(f'line {reader.line_num}: CSV invalid: {error}')
        else:
            for line, raw in enumerate(text.splitlines(), 1):
                if raw.strip():
                    add(json_value(raw, f'line {line}: JSONL'), line)
        return actions

    def run_batch(self, token, state, form):
        continuing = self.one(form, 'continue') == '1'
        if continuing:
            actions = state.get('pending_batch', [])
        else:
            text = self.one(form, 'file') or self.one(form, 'batch')
            actions = self.parse_batch(text, self.one(form, 'file_filename'), self.one(form, 'format'))
        if audit_remaining(state) < 2:
            self.batch_page(token, state, f'<p class="error">{h(CAPACITY_MESSAGE)}</p>')
            return
        if not continuing:
            state['last_results'] = []
            state['last_batch_counts'] = {}
        started = self.server.monotonic()
        index = 0
        while index < len(actions):
            if self.server.monotonic() - started >= self.server.batch_seconds or audit_remaining(state) < 2:
                break
            action = actions[index]
            # Older pending batches also receive visible, line-specific errors.
            try:
                result = self.server.store.check(state, action)
            except StoreError as error:
                raise StoreError(f'line {action.get("_line", index + 1)}: {error}')
            if result['line'] is None:
                result['line'] = len(state['last_results']) + 1
            state['last_results'].append(result)
            index += 1
        state['pending_batch'] = actions[index:]
        counts = {}
        for result in state['last_results']:
            counts[result['reason']] = counts.get(result['reason'], 0) + 1
        state['last_batch_counts'] = counts
        append_event(state, 'batch.run', 'system', 'system', data={'processed': index, 'remaining': len(state['pending_batch']), 'counts': counts})
        self.server.store.save(token, state)
        self.batch_page(token, state)

    def batch_page(self, token, state, note=''):
        pending = bool(state.get('pending_batch'))
        capacity = audit_remaining(state) < 2
        if capacity:
            if CAPACITY_MESSAGE not in note:
                note += f'<p class="error">{h(CAPACITY_MESSAGE)}</p>'
            if pending:
                note += '<p>Unprocessed actions are retained in the JSON export. Continue cannot run at this capacity.</p>'
        elif pending:
            note += '<p>Processing paused at the time budget. Use Continue to process the remaining actions.</p>'
            note += self.form_html('/w/' + token + '/batch', 'Continue', '<input type="hidden" name="continue" value="1">')
        sample = '\n'.join(json.dumps(item) for item in state.get('sample_actions', []))
        fields = f'<label>Paste JSONL or CSV<textarea name="batch">{h(sample)}</textarea></label><label>Format<select name="format"><option>jsonl</option><option>csv</option></select></label><label>Or upload a UTF-8 file up to 1 MB<input type="file" name="file" accept=".jsonl,.csv"></label>'
        content = note + self.form_html('/w/' + token + '/batch', 'Run batch', fields, True)
        content += f'<p>Counts: {h(json.dumps(state.get("last_batch_counts", {})))}</p><p><a href="{h(self.url("/w/" + token + "/batch/results.csv"))}">Download results CSV</a></p>'
        fields = ('line', 'agent_id', 'grant_id', 'scope', 'params', 'decision', 'reason', 'detail')
        rows = ''.join('<tr>' + ''.join('<td>' + h(json.dumps(item.get(key)) if key == 'params' else item.get(key, '')) + '</td>' for key in fields) + '</tr>' for item in state.get('last_results', []))
        content += '<table><tr>' + ''.join('<th>' + h(key) + '</th>' for key in fields) + '</tr>' + rows + '</table>'
        self.page('Batch replay', content, token=token)

    def results_csv(self, state):
        output = io.StringIO(newline='')
        fields = ['line', 'decision', 'allow', 'reason', 'detail', 'agent_id', 'grant_id', 'scope', 'params', 'at']
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for result in state.get('last_results', []):
            writer.writerow({key: csv_cell(canonical(result.get(key)) if key == 'params' else result.get(key)) for key in fields})
        self.send_data(200, output.getvalue(), 'text/csv; charset=utf-8', workspace=True, disposition='attachment; filename="grantlatch-results.csv"')

    def audit_page(self, token, state):
        ok, bad = verify_chain(state['audit'])
        head = state['audit'][-1]['hash'] if state['audit'] else '0' * 64
        content = f'<p><strong>{"Chain verifies" if ok else "Chain broken at sequence " + str(bad)}</strong></p><a href="{h(self.url("/w/" + token + "/audit"))}">Verify chain</a><p>Head hash: <code>{h(head)}</code></p><p>Remaining ordinary capacity: {audit_remaining(state)}. Reserved lifecycle capacity: {audit_remaining(state, True)}. Total event ceiling: {MAX_AUDIT}. The chain detects edits, not a rebuild by the workspace owner.</p>'
        if audit_remaining(state) < 2:
            content += f'<p class="error">{h(CAPACITY_MESSAGE)}</p>'
        if state.get('sample'):
            content += self.form_html('/w/' + token + '/audit/tamper', 'Tamper (sample only)')
        rows = ''.join(f'<tr><td>{event["seq"]}</td><td>{h(event["event"])}</td><td>{h(event["actor_type"])}</td><td>{h(event["actor_id"])}</td><td>{h(json.dumps(event["data"]))}</td></tr>' for event in state['audit'])
        self.page('Audit trail', content + '<table><tr><th>Seq</th><th>Event</th><th>Actor type</th><th>Actor</th><th>Data</th></tr>' + rows + '</table>', token=token)

    def export(self, token, state):
        ok, bad = verify_chain(state['audit'])
        exported = {key: value for key, value in state.items() if key != 'chain_on_load'}
        exported['chain_verify'] = {'ok': ok, 'first_bad_seq': bad}
        exported['offline_verification'] = 'For each event, remove hash and compute SHA-256 over prev_hash + canonical JSON (sorted keys, compact separators, ASCII); require sequential seq and matching prev_hash.'
        self.send_data(200, json.dumps(exported, indent=2, sort_keys=True), 'application/json; charset=utf-8', workspace=True, disposition='attachment; filename="grantlatch-export.json"')


def make_server(host='127.0.0.1', port=8080, *, data_dir=None, public_base_url=None,
                clock=time.time, monotonic=time.monotonic, data_cap_mb=200,
                max_connections=32, request_timeout=10, batch_seconds=4):
    data_dir = data_dir or os.environ.get('DATA_DIR', os.path.join(os.path.dirname(__file__), 'data'))
    store = WorkspaceStore(data_dir, clock=clock, data_cap_mb=data_cap_mb)
    server = AppServer((host, int(port)), Handler, store, public_base_url or f'http://{host}:{port}',
                       max_connections, request_timeout, monotonic, batch_seconds)
    if public_base_url is None and int(port) == 0:
        server.public_base_url = f'http://{host}:{server.server_port}'
        server.public = urlsplit(server.public_base_url)
    return server


def start_cleanup(server):
    server.store.sweep()
    server.cleanup_stop = threading.Event()
    def run():
        while not server.cleanup_stop.wait(86400):
            server.store.sweep()
    server.cleanup_thread = threading.Thread(target=run, name='grantlatch-daily-cleanup', daemon=True)
    server.cleanup_thread.start()


def main():
    server = make_server(os.environ.get('APP_HOST', '127.0.0.1'), int(os.environ.get('PORT', '8080')),
                         data_dir=os.environ['DATA_DIR'],
                         public_base_url=os.environ.get('PUBLIC_BASE_URL', 'https://app-grantlatch.manykiln.com'),
                         data_cap_mb=os.environ.get('APP_DATA_CAP_MB', '200'))
    start_cleanup(server)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.cleanup_stop.set()
        server.server_close()


if __name__ == '__main__':
    main()
