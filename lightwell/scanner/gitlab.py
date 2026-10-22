"""
GitLab side of the scanner: a project -> the dependency manifests inside it. Works for gitlab.com and for any
self-hosted GitLab the operator has listed (see repo.allowed_gitlab_hosts).

Per project: the project (default branch, visibility), the commit, the file tree (paged), then one raw fetch per
manifest. A token is sent only to the host it was configured for, and only through the PRIVATE-TOKEN header.
Without a token only public projects can be read.
"""
from __future__ import annotations

import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from .http import UpstreamError, request
from .parse import manifest_kind
from .repo import RepoRef, RepoSnapshot

PER_PAGE = 100
MAX_PAGES = 50                                        # 5,000 tree entries


class GitLabClient:
    def __init__(self, host: str = 'gitlab.com', token: str = '', timeout: float = 20, max_manifests: int = 60,
                 max_bytes: int = 1_000_000, workers: int = 6):
        self.host = host
        self.api = f'https://{host}/api/v4'
        self.token = token.strip()
        self.timeout = timeout
        self.max_manifests = max_manifests
        self.max_bytes = max_bytes
        self.workers = workers

    # ---------------------------------------------------------------- plumbing
    def _headers(self) -> dict:
        h = {'Accept': 'application/json'}
        if self.token:
            h['PRIVATE-TOKEN'] = self.token
        return h

    def _get(self, path: str, **kw):
        try:
            return request('GitLab', f'{self.api}{path}', headers=self._headers(), timeout=self.timeout, **kw)
        except UpstreamError as exc:
            raise self._explain(exc)

    def _explain(self, exc: UpstreamError) -> UpstreamError:
        headers = getattr(exc, 'headers', {}) or {}
        if exc.status == 429:
            wait = headers.get('retry-after')
            return UpstreamError('GitLab', f'rate limit reached on {self.host}.' + (f' Try again in {wait} seconds.' if wait else '')
                                 + ' A GitLab token raises the limit.', 429)
        if exc.status == 404:
            return UpstreamError('GitLab', 'project, branch or path not found. A private project needs a GitLab token for ' + self.host + '.', 404)
        if exc.status in (401, 403):
            return UpstreamError('GitLab', f'access refused (HTTP {exc.status}). Check that the token for {self.host} is valid '
                                           'and has read_api or read_repository access.', exc.status)
        return exc

    # ---------------------------------------------------------------- snapshot
    def snapshot(self, ref: RepoRef) -> RepoSnapshot:
        pid = urllib.parse.quote(ref.path, safe='')
        meta, _ = self._get(f'/projects/{pid}')
        branch = ref.ref or meta.get('default_branch') or 'main'                      # type: ignore[union-attr]
        commit, _ = self._get(f'/projects/{pid}/repository/commits/{urllib.parse.quote(branch, safe="")}')
        sha = commit['id']                                                              # type: ignore[index]
        snap = RepoSnapshot(ref.slug, branch, sha, (meta.get('visibility') or 'public') != 'public')   # type: ignore[union-attr]

        entries, page, more = [], 1, True
        while more and page <= MAX_PAGES:
            rows, headers = self._get(f'/projects/{pid}/repository/tree?recursive=true&per_page={PER_PAGE}&page={page}'
                                      f'&ref={urllib.parse.quote(sha, safe="")}')
            entries += rows or []                                                       # type: ignore[operator]
            more = bool(headers.get('x-next-page')) and bool(rows)
            page += 1
        if more:
            snap.notes.append(f'The project tree has more than {PER_PAGE * MAX_PAGES} entries, so some manifests may be missing.')

        prefix = ref.subpath.strip('/')
        found = []
        for item in entries:
            path = item.get('path', '')
            if item.get('type') != 'blob' or manifest_kind(path) is None:
                continue
            if prefix and not (path == prefix or path.startswith(prefix + '/')):
                continue
            found.append(path)
        if len(found) > self.max_manifests:
            snap.notes.append(f'{len(found)} manifests found; only the first {self.max_manifests} were read.')
            found = found[:self.max_manifests]
        if not found:
            snap.notes.append('No supported dependency manifests were found.')
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            texts = list(pool.map(lambda p: self._fetch(pid, sha, p), found))
        for path, text in zip(found, texts):
            if text is None:
                snap.notes.append(f'{path}: could not be fetched, or is larger than {self.max_bytes // 1000} KB.')
            else:
                snap.manifests.append((path, text))
        return snap

    def _fetch(self, pid: str, sha: str, path: str) -> str | None:
        try:
            body, _ = request('GitLab', f'{self.api}/projects/{pid}/repository/files/{urllib.parse.quote(path, safe="")}/raw'
                                        f'?ref={urllib.parse.quote(sha, safe="")}',
                              headers=self._headers(), timeout=self.timeout, raw=True, max_bytes=self.max_bytes)
            return body.decode('utf-8', errors='replace')                               # type: ignore[union-attr]
        except UpstreamError:
            return None
