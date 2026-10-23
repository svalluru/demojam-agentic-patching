"""
Scan persistence: one JSON file per scan under data/scans, plus the saved repository list.
Plain files on purpose, so a result can be read, diffed and deleted by hand.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from pathlib import Path

_LOCK = threading.Lock()
SCAN_ID = re.compile(r'^[0-9a-f]{12}$')


class Store:
    def __init__(self, data_dir: Path):
        self.dir = Path(data_dir)
        self.scans = self.dir / 'scans'
        self.repos_file = self.dir / 'repos.json'

    def _write(self, path: Path, obj: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix='.tmp')
        try:
            with os.fdopen(fd, 'w') as fh:
                json.dump(obj, fh, indent=2)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def save_scan(self, scan: dict) -> None:
        if not SCAN_ID.match(scan['id']):
            raise ValueError('bad scan id')
        with _LOCK:
            self._write(self.scans / f'{scan["id"]}.json', scan)

    def load_scan(self, scan_id: str) -> dict | None:
        if not SCAN_ID.match(scan_id):
            return None
        f = self.scans / f'{scan_id}.json'
        try:
            return json.loads(f.read_text())
        except (OSError, ValueError):
            return None

    def list_scans(self, limit: int = 50) -> list[dict]:
        out = []
        for f in sorted(self.scans.glob('*.json'), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]:
            try:
                out.append(json.loads(f.read_text()))
            except (OSError, ValueError):
                continue
        return out

    def load_repos(self) -> list[str]:
        try:
            data = json.loads(self.repos_file.read_text())
            return [r for r in data.get('repos', []) if isinstance(r, str)]
        except (OSError, ValueError):
            return []

    def save_repos(self, repos: list[str]) -> None:
        with _LOCK:
            self._write(self.repos_file, {'repos': repos})
