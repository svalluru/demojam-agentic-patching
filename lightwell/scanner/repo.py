"""
Repository references and the code hosts behind them.

A scan starts from a URL. parse_repo() turns it into a RepoRef that says which host it lives on and how to reach it.
Only github.com, gitlab.com and GitLab hosts the operator has listed are accepted: this server fetches whatever
host a user types, so an open list would let a URL point it at internal addresses.

RepoRouter hands a RepoRef to the right client. DemoRepos replays recorded repositories and opens no socket.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from .http import UpstreamError

_SEGMENT = re.compile(r'^[A-Za-z0-9_.-]{1,100}$')
_HOST = re.compile(r'^[A-Za-z0-9.-]+(:\d{1,5})?$')
GITHUB_HOST = 'github.com'
GITLAB_HOST = 'gitlab.com'


@dataclass
class RepoRef:
    kind: str                      # github | gitlab
    host: str
    path: str                      # owner/repo, or group/subgroup/project
    ref: str = ''
    subpath: str = ''

    @property
    def slug(self) -> str:
        """Short name for display and for recorded files. GitHub keeps owner/repo, GitLab includes the host."""
        return self.path if self.kind == 'github' else f'{self.host}/{self.path}'

    @property
    def owner(self) -> str:
        return self.path.split('/')[0]

    @property
    def repo(self) -> str:
        return self.path.split('/')[1] if '/' in self.path else ''


@dataclass
class RepoSnapshot:
    slug: str
    ref: str
    commit: str
    private: bool = False
    manifests: list[tuple[str, str]] = field(default_factory=list)   # (path, text)
    notes: list[str] = field(default_factory=list)   # shown on the page under the repository


def allowed_gitlab_hosts(extra: list[str] | tuple[str, ...] = ()) -> list[str]:
    hosts = [GITLAB_HOST]
    for h in extra:
        h = h.strip().lower()
        if h and _HOST.match(h) and h not in hosts:
            hosts.append(h)
    return hosts


def _clean(segment: str) -> str:
    seg = urllib.parse.unquote(segment)
    if seg in ('.', '..') or not _SEGMENT.match(seg):
        raise ValueError('invalid name in the repository path')
    return seg


def parse_repo(spec: str, gitlab_hosts: list[str] | tuple[str, ...] = ()) -> RepoRef:
    """Accepted forms:
        owner/repo                                   GitHub
        github.com/owner/repo, https://github.com/owner/repo(.git), .../tree/<ref>/<folder>
        gitlab.com/group/project, https://gitlab.com/group/subgroup/project(.git), .../-/tree/<ref>/<folder>
        the same for any GitLab host passed in gitlab_hosts
    A branch name containing a slash cannot be told apart from a folder in a tree URL, so the first segment after
    tree/ is taken as the ref."""
    s = (spec or '').strip()
    if not s or len(s) > 400:
        raise ValueError('empty or too long repository reference')
    s = re.sub(r'^https?://', '', s, flags=re.I)
    s = s.split('?', 1)[0].split('#', 1)[0].strip('/')
    parts = s.split('/')
    first = parts[0].lower()
    if first.startswith('www.'):
        first = first[4:]
    hosts = allowed_gitlab_hosts(gitlab_hosts)

    if first == GITHUB_HOST:
        kind, host, rest = 'github', GITHUB_HOST, parts[1:]
    elif first in hosts:
        kind, host, rest = 'gitlab', first, parts[1:]
    elif '.' in parts[0] or ':' in parts[0]:
        raise ValueError(f'host {parts[0]} is not supported. Supported: github.com, ' + ', '.join(hosts))
    else:
        kind, host, rest = 'github', GITHUB_HOST, parts

    ref = sub = ''
    if kind == 'github':
        if len(rest) < 2:
            raise ValueError('expected owner/repo')
        path_parts, tail = rest[:2], rest[2:]
        if tail:
            if tail[0] != 'tree' or len(tail) < 2:
                raise ValueError('expected owner/repo or owner/repo/tree/<ref>/<folder>')
            ref, sub = urllib.parse.unquote(tail[1]), '/'.join(urllib.parse.unquote(p) for p in tail[2:])
    else:
        if '-' in rest:                                    # GitLab separates the project path from the view with /-/
            i = rest.index('-')
            path_parts, tail = rest[:i], rest[i + 1:]
            if tail:
                if tail[0] != 'tree' or len(tail) < 2:
                    raise ValueError('expected group/project or group/project/-/tree/<ref>/<folder>')
                ref, sub = urllib.parse.unquote(tail[1]), '/'.join(urllib.parse.unquote(p) for p in tail[2:])
        else:
            path_parts = rest
        if len(path_parts) < 2:
            raise ValueError('expected group/project')
    path_parts = [_clean(p) for p in path_parts]
    path_parts[-1] = re.sub(r'\.git$', '', path_parts[-1])
    if not path_parts[-1]:
        raise ValueError('invalid name in the repository path')
    if '..' in ref.split('/') or '..' in sub.split('/'):
        raise ValueError('invalid ref or folder')
    return RepoRef(kind, host, '/'.join(path_parts), ref, sub)


class RepoRouter:
    """Sends a RepoRef to the client for its host."""

    def __init__(self, github, gitlab: dict):
        self.github = github
        self.gitlab = gitlab                                # host -> GitLabClient

    def snapshot(self, ref: RepoRef) -> RepoSnapshot:
        if ref.kind == 'github':
            return self.github.snapshot(ref)
        client = self.gitlab.get(ref.host)
        if client is None:
            raise UpstreamError('GitLab', f'{ref.host} is not configured')
        return client.snapshot(ref)


class DemoRepos:
    """Serves recorded repositories from demo/repos/<slug with / as __>.json. No socket."""

    def __init__(self, directory: Path):
        self.dir = Path(directory)

    @staticmethod
    def _file(slug: str) -> str:
        return slug.replace('/', '__') + '.json'

    def available(self) -> list[str]:
        return sorted(p.stem.replace('__', '/') for p in self.dir.glob('*.json')) if self.dir.exists() else []

    def snapshot(self, ref: RepoRef) -> RepoSnapshot:
        f = self.dir / self._file(ref.slug)
        if not f.is_file():
            have = ', '.join(self.available()) or 'none'
            raise UpstreamError('demo', f'{ref.slug} was not recorded. Demo mode serves only recorded repositories ({have}). '
                                        'Switch to live mode to scan any repository.')
        data = json.loads(f.read_text())
        return RepoSnapshot(ref.slug, data.get('ref', ''), data.get('commit', ''), False,
                            [(p, t) for p, t in data.get('manifests', {}).items()], list(data.get('notes', [])))
