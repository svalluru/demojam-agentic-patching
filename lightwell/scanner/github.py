"""
GitHub side of the scanner: a repository -> the dependency manifests inside it.

Three API calls per repository (repo, commit, tree), then one fetch per manifest. Without a token, manifests come
from raw.githubusercontent.com, which does not count against the 60-per-hour unauthenticated API limit. With a
token they come from the contents API, which is also what makes private repositories readable.
"""
from __future__ import annotations

import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from .http import UpstreamError, request
from .parse import manifest_kind
from .repo import RepoRef, RepoSnapshot


class GitHubClient:
    def __init__(self, token: str = '', api: str = 'https://api.github.com',
                 raw: str = 'https://raw.githubusercontent.com', timeout: float = 20,
                 max_manifests: int = 60, max_bytes: int = 1_000_000, workers: int = 6):
        self.token = token.strip()
        self.api = api.rstrip('/')
        self.raw = raw.rstrip('/')
        self.timeout = timeout
        self.max_manifests = max_manifests
        self.max_bytes = max_bytes
        self.workers = workers

    # ---------------------------------------------------------------- plumbing
    def _headers(self, accept: str = 'application/vnd.github+json') -> dict:
        h = {'Accept': accept, 'X-GitHub-Api-Version': '2022-11-28'}
        if self.token:
            h['Authorization'] = f'Bearer {self.token}'
        return h

    def _get(self, path: str, **kw):
        try:
            return request('GitHub', f'{self.api}{path}', headers=self._headers(kw.pop('accept', 'application/vnd.github+json')),
                           timeout=self.timeout, **kw)
        except UpstreamError as exc:
            raise self._explain(exc)

    @staticmethod
    def _explain(exc: UpstreamError) -> UpstreamError:
        headers = getattr(exc, 'headers', {}) or {}
        if exc.status in (403, 429) and headers.get('x-ratelimit-remaining') == '0':
            reset = ''
            if exc.reset and exc.reset.isdigit():
                reset = ' It resets at ' + time.strftime('%H:%M UTC', time.gmtime(int(exc.reset))) + '.'
            return UpstreamError('GitHub', 'API rate limit reached. Set GITHUB_TOKEN to raise the limit.' + reset, exc.status)
        if exc.status == 404:
            return UpstreamError('GitHub', 'repository, branch or path not found. A private repository needs GITHUB_TOKEN.', 404)
        if exc.status in (401, 403):
            return UpstreamError('GitHub', f'access refused (HTTP {exc.status}). Check that GITHUB_TOKEN is valid and can read the repository.', exc.status)
        return exc

    # ---------------------------------------------------------------- snapshot
    def snapshot(self, ref: RepoRef) -> RepoSnapshot:
        o, r = urllib.parse.quote(ref.owner), urllib.parse.quote(ref.repo)
        meta, _ = self._get(f'/repos/{o}/{r}')
        branch = ref.ref or meta.get('default_branch') or 'main'                    # type: ignore[union-attr]
        commit, _ = self._get(f'/repos/{o}/{r}/commits/{urllib.parse.quote(branch, safe="")}')
        sha = commit['sha']                                                          # type: ignore[index]
        tree, _ = self._get(f'/repos/{o}/{r}/git/trees/{sha}?recursive=1')
        snap = RepoSnapshot(ref.slug, branch, sha, bool(meta.get('private')))        # type: ignore[union-attr]
        if tree.get('truncated'):                                                    # type: ignore[union-attr]
            snap.notes.append('The repository tree is too large for one listing, so some manifests may be missing.')
        prefix = ref.subpath.strip('/')
        found = []
        for item in tree.get('tree', []):                                            # type: ignore[union-attr]
            path = item.get('path', '')
            if item.get('type') != 'blob' or manifest_kind(path) is None:
                continue
            if prefix and not (path == prefix or path.startswith(prefix + '/')):
                continue
            if item.get('size', 0) > self.max_bytes:
                snap.notes.append(f'{path}: skipped, larger than {self.max_bytes // 1000} KB.')
                continue
            found.append(path)
        if len(found) > self.max_manifests:
            snap.notes.append(f'{len(found)} manifests found; only the first {self.max_manifests} were read.')
            found = found[:self.max_manifests]
        if not found:
            snap.notes.append('No supported dependency manifests were found.')
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            texts = list(pool.map(lambda p: self._fetch(ref, sha, p), found))
        for path, text in zip(found, texts):
            if text is None:
                snap.notes.append(f'{path}: could not be fetched.')
            else:
                snap.manifests.append((path, text))
        return snap

    def _fetch(self, ref: RepoRef, sha: str, path: str) -> str | None:
        quoted = urllib.parse.quote(path)
        owner, repo = urllib.parse.quote(ref.owner), urllib.parse.quote(ref.repo)
        try:
            if self.token:
                body, _ = request('GitHub', f'{self.api}/repos/{owner}/{repo}/contents/{quoted}?ref={sha}',
                                  headers=self._headers('application/vnd.github.raw'), timeout=self.timeout, raw=True,
                                  max_bytes=self.max_bytes)
            else:
                body, _ = request('GitHub', f'{self.raw}/{owner}/{repo}/{sha}/{quoted}', headers={'Accept': '*/*'},
                                  timeout=self.timeout, raw=True, max_bytes=self.max_bytes)
            return body.decode('utf-8', errors='replace')                             # type: ignore[union-attr]
        except UpstreamError:
            return None
