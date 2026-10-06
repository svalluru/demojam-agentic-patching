#!/usr/bin/env python3
"""
Lightweight dev server for the Agentic Patching Console frontend.
Serves index.html and proxies CVE requests to Red Hat Insights
using LIGHTSPEED_CLIENT_ID / LIGHTSPEED_CLIENT_SECRET for OAuth.
Optionally proxies /api/state, /api/start, /api/approve, /api/deny
to a running cve_console.py backend.

Usage:
    python3 server.py
    python3 server.py --env ../src/openshift/.env.openshift
    python3 server.py --backend http://127.0.0.1:8787
"""
import json
import logging
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

LOG = logging.getLogger('frontend')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s %(message)s',
    datefmt='%H:%M:%S',
)

FRONTEND_DIR = Path(__file__).resolve().parent
HOST = os.environ.get('FRONTEND_HOST', '127.0.0.1')
PORT = int(os.environ.get('FRONTEND_PORT', '8788'))
BACKEND_URL = os.environ.get('CVE_CONSOLE_BACKEND', 'http://127.0.0.1:8787')

RHSSO_TOKEN_URL = 'https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token'
INSIGHTS_BASE = 'https://console.redhat.com/api'
CVE_LIST_PATH = '/vulnerability/v1/vulnerabilities/cves'

PROXY_PATHS = {'/api/state', '/api/start', '/api/approve', '/api/deny',
               '/api/settings', '/api/flow-log', '/api/what-if', '/api/why',
               '/api/approval-targets'}

_token_cache: dict = {}


def load_dotenv(path: str) -> None:
    p = Path(path)
    if not p.exists():
        LOG.warning('env file not found: %s', path)
        return
    for raw in p.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    LOG.info('Loaded env from %s', path)


def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def get_access_token() -> str:
    now = time.time()
    cached = _token_cache.get('token')
    expires_at = _token_cache.get('expires_at', 0)
    if cached and expires_at > now + 30:
        return cached

    client_id = os.environ.get('LIGHTSPEED_CLIENT_ID', '').strip()
    client_secret = os.environ.get('LIGHTSPEED_CLIENT_SECRET', '').strip()
    if not client_id or not client_secret:
        raise RuntimeError(
            'LIGHTSPEED_CLIENT_ID and LIGHTSPEED_CLIENT_SECRET are required. '
            'Pass --env path/to/.env.openshift or export them.'
        )

    body = urllib.parse.urlencode({
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'api.console',
    }).encode()
    req = urllib.request.Request(
        RHSSO_TOKEN_URL, data=body, method='POST',
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
    )
    with urllib.request.urlopen(req, timeout=20, context=_ssl_ctx()) as r:
        result = json.loads(r.read().decode())

    token = result.get('access_token', '')
    if not token:
        raise RuntimeError(f'SSO response missing access_token: {json.dumps(result)[:200]}')

    _token_cache['token'] = token
    _token_cache['expires_at'] = now + int(result.get('expires_in', 300))
    LOG.info('OAuth token refreshed (expires_in=%ss)', result.get('expires_in'))
    return token


def fetch_cves(limit: int = 20, offset: int = 0) -> dict:
    token = get_access_token()
    params = urllib.parse.urlencode({
        'limit': limit,
        'offset': offset,
        'sort': '-public_date',
        'cvss_from': 0.0,
        'cvss_to': 10.0,
        'impact': '1,2,4,5,7',
        'rule_presence': 'true,false',
        'known_exploit': 'true,false',
        'advisory_available': 'true',
        'affecting_host_type': 'rpmdnf',
    })
    url = f'{INSIGHTS_BASE}{CVE_LIST_PATH}?{params}'
    req = urllib.request.Request(url, headers={
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json',
    })
    LOG.info('GET %s (limit=%d offset=%d)', CVE_LIST_PATH, limit, offset)
    t0 = time.monotonic()
    with urllib.request.urlopen(req, timeout=120, context=_ssl_ctx()) as r:
        raw = json.loads(r.read().decode())
    elapsed = time.monotonic() - t0
    LOG.info('CVE fetch done in %.1fs — %d items', elapsed, len(raw.get('data', [])))
    return raw


def parse_cve_item(item: dict) -> dict:
    cve_id = item.get('id', '')
    attrs = item.get('attributes', {})
    cvss = attrs.get('cvss3_score') or attrs.get('cvss2_score')
    try:
        cvss = float(cvss) if cvss is not None else None
    except (ValueError, TypeError):
        cvss = None
    return {
        'id': cve_id,
        'description': attrs.get('description', ''),
        'cvss': cvss,
        'impact': attrs.get('impact', ''),
        'systems_affected': attrs.get('systems_affected'),
        'public_date': attrs.get('public_date', ''),
        'known_exploit': attrs.get('known_exploit', False),
        'advisory_available': attrs.get('advisory_available', False),
        'status': attrs.get('status', ''),
        'rhel_versions': attrs.get('rhel_versions', []),
    }


def proxy_to_backend(method: str, path: str, query: str, body: bytes | None) -> tuple[int, bytes]:
    url = f'{BACKEND_URL}{path}'
    if query:
        url += f'?{query}'
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header('Accept', 'application/json')
    if body:
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as exc:
        resp = b''
        try:
            resp = exc.read()
        except Exception:
            pass
        return exc.code, resp or json.dumps({'ok': False, 'error': f'HTTP {exc.code}'}).encode()
    except Exception as exc:
        return 502, json.dumps({'ok': False, 'error': f'Backend not available ({type(exc).__name__})'}).encode()


class Handler(BaseHTTPRequestHandler):
    def respond(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _handle_proxy(self, method: str) -> bool:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/') or '/'
        if path not in PROXY_PATHS:
            return False
        body = None
        if method == 'POST':
            length = int(self.headers.get('Content-Length', '0') or '0')
            body = self.rfile.read(length) if length else None
        status, resp_body = proxy_to_backend(method, path, parsed.query or '', body)
        self.respond(status, 'application/json', resp_body)
        return True

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/') or '/'

        if path == '/' or path == '/index.html':
            html = (FRONTEND_DIR / 'index.html').read_bytes()
            self.respond(200, 'text/html; charset=utf-8', html)
            return

        if path == '/api/cves':
            try:
                query = parse_qs(parsed.query or '')
                limit = int((query.get('limit') or ['20'])[0])
                offset = int((query.get('offset') or ['0'])[0])
                raw = fetch_cves(limit=min(limit, 50), offset=max(0, offset))
                cves = [parse_cve_item(item) for item in raw.get('data', [])]
                meta = raw.get('meta', {})
                payload = {
                    'ok': True,
                    'cves': cves,
                    'count': len(cves),
                    'limit': limit,
                    'offset': offset,
                    'has_more': (offset + len(cves)) < meta.get('total_items', 0),
                    'total_items': meta.get('total_items', 0),
                    'source': 'insights_rest',
                }
                self.respond(200, 'application/json', json.dumps(payload).encode())
            except Exception as exc:
                LOG.exception('CVE fetch failed')
                self.respond(500, 'application/json',
                             json.dumps({'ok': False, 'error': str(exc)}).encode())
            return

        if self._handle_proxy('GET'):
            return

        if path == '/healthz':
            self.respond(200, 'text/plain', b'ok')
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self._handle_proxy('POST'):
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, fmt, *args):
        try:
            msg = fmt % args
        except Exception:
            return
        if '/healthz' not in msg:
            LOG.debug('HTTP %s', msg)


def main():
    global BACKEND_URL

    if '--env' in sys.argv:
        idx = sys.argv.index('--env')
        if idx + 1 < len(sys.argv):
            load_dotenv(sys.argv[idx + 1])

    if '--backend' in sys.argv:
        idx = sys.argv.index('--backend')
        if idx + 1 < len(sys.argv):
            BACKEND_URL = sys.argv[idx + 1].rstrip('/')

    default_env = FRONTEND_DIR.parent / 'src' / 'openshift' / '.env.openshift'
    if default_env.exists():
        load_dotenv(str(default_env))

    cid = os.environ.get('LIGHTSPEED_CLIENT_ID', '')
    if not cid:
        LOG.error('LIGHTSPEED_CLIENT_ID not set. Pass --env or export it.')
        sys.exit(1)
    LOG.info('Lightspeed client_id=%s...%s', cid[:8], cid[-4:])
    LOG.info('Backend proxy target: %s', BACKEND_URL)

    server = ThreadingHTTPServer((HOST, PORT), Handler)
    LOG.info('Frontend server listening on http://%s:%s', HOST, PORT)
    server.serve_forever()


if __name__ == '__main__':
    main()
