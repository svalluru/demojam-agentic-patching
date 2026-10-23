"""
Small HTTP helper for the services the scanner talks to (OSV.dev, GitHub, GitLab, Red Hat).

Standard library only. One failure type, UpstreamError, names the service and
carries the HTTP status, so a caller can tell a rate limit from a missing repo
without parsing text. Secrets are never put in an exception message.
"""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = 'lightwell-scanner/0.1 (+demojam)'
RETRY_STATUS = (429, 500, 502, 503, 504)


class UpstreamError(RuntimeError):
    def __init__(self, service: str, message: str, status: int | None = None,
                 reset: str | None = None):
        super().__init__(f'{service}: {message}')
        self.service = service
        self.message = message
        self.status = status
        self.reset = reset


def request(service: str, url: str, *, method: str = 'GET', body: object | None = None,
            headers: dict | None = None, timeout: float = 20, retries: int = 2,
            raw: bool = False, form: dict | None = None, max_bytes: int | None = None, cafile: str | None = None) -> tuple[object, dict]:
    """Returns (payload, response headers). payload is parsed JSON, or bytes when raw.
    `form` sends application/x-www-form-urlencoded instead of a JSON body. `max_bytes` stops a raw download that
    is larger than expected instead of reading it all. Neither the body nor the form is ever included in an
    error message. `cafile` names a CA bundle to trust, for a server whose certificate comes from a private authority."""
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {'User-Agent': USER_AGENT, 'Accept': 'application/json'}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs['Content-Type'] = 'application/x-www-form-urlencoded'
    elif data is not None:
        hdrs['Content-Type'] = 'application/json'
    hdrs.update(headers or {})
    ctx = ssl.create_default_context(cafile=cafile)
    last: UpstreamError | None = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                payload = resp.read(max_bytes + 1) if max_bytes else resp.read()
                if max_bytes and len(payload) > max_bytes:
                    raise UpstreamError(service, f'{_safe(url)} is larger than {max_bytes // 1000} KB')
                info = {k.lower(): v for k, v in resp.headers.items()}
                if raw:
                    return payload, info
                return (json.loads(payload) if payload else {}), info
        except urllib.error.HTTPError as exc:
            info = {k.lower(): v for k, v in (exc.headers or {}).items()}
            last = UpstreamError(service, f'HTTP {exc.code} for {_safe(url)}', exc.code,
                                 info.get('x-ratelimit-reset'))
            last.headers = info                      # type: ignore[attr-defined]
            if exc.code in RETRY_STATUS and attempt < retries:
                time.sleep(1.5 * (attempt + 1))
                continue
            raise last
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, ConnectionError) as exc:
            last = UpstreamError(service, f'could not reach {_safe(url)} ({exc})')
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
                continue
            raise last
        except ValueError as exc:
            raise UpstreamError(service, f'answer from {_safe(url)} was not JSON ({exc})')
    raise last or UpstreamError(service, 'request failed')


def _safe(url: str) -> str:
    return url.split('?', 1)[0]
