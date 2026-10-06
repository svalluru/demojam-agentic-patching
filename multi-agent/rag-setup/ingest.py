#!/usr/bin/env python3
"""Ingest documents into the RAG vector store through the Llama Stack route.

  ./ingest.py --route https://llamastack-... --dir ./data
  ./ingest.py --route https://llamastack-... --query "drain timeout failures"
  ./ingest.py --route https://llamastack-... --list

Uses the Llama Stack 0.7.x OpenAI-compatible APIs: upload to /v1/files, attach
to a vector store, search via /v1/vector_stores/{id}/search. The embedding model
is discovered from /v1/models rather than hardcoded. Standard library only.

Prints the vs_... store id on success — that is the value to set as
VECTOR_DB_ID for the console.
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import ssl
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

TEXT_SUFFIXES = {'.md', '.txt', '.json', '.yaml', '.yml', '.log', '.csv'}


def _ctx() -> ssl.SSLContext:
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def call(route: str, path: str, method: str = 'GET', body: dict | None = None,
         timeout: int = 300) -> tuple[int, object]:
    req = urllib.request.Request(
        f'{route.rstrip("/")}{path}', method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={'Content-Type': 'application/json'} if body is not None else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw.strip() else None)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw[:600]


def upload_file(route: str, path: Path, timeout: int = 300) -> str:
    """POST /v1/files as multipart/form-data. Returns the file id."""
    boundary = f'----llamastack{uuid.uuid4().hex}'
    ctype = mimetypes.guess_type(path.name)[0] or 'text/plain'
    parts: list[bytes] = []
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="purpose"\r\n\r\nassistants\r\n'.encode())
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
        f'Content-Type: {ctype}\r\n\r\n'.encode()
        + path.read_bytes() + b'\r\n'
    )
    parts.append(f'--{boundary}--\r\n'.encode())
    data = b''.join(parts)

    req = urllib.request.Request(
        f'{route.rstrip("/")}/v1/files', data=data, method='POST',
        headers={'Content-Type': f'multipart/form-data; boundary={boundary}',
                 'Content-Length': str(len(data))},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
            return json.loads(r.read().decode())['id']
    except urllib.error.HTTPError as e:
        sys.exit(f'  FAILED upload {path.name}: HTTP {e.code} {e.read().decode()[:300]}')


def embedding_model(route: str) -> str:
    code, resp = call(route, '/v1/models', timeout=60)
    if code != 200:
        sys.exit(f'  FAILED to list models: HTTP {code} {resp}')
    items = resp.get('data') if isinstance(resp, dict) else resp
    for m in items or []:
        meta = m.get('custom_metadata') or {}
        if meta.get('model_type') == 'embedding':
            return m['id']
    sys.exit('  No embedding model registered on this Llama Stack')


def find_or_create_store(route: str, name: str) -> str:
    code, resp = call(route, '/v1/vector_stores', timeout=60)
    if code == 200 and isinstance(resp, dict):
        for s in resp.get('data', []):
            if s.get('name') == name:
                print(f'  vector store "{name}" exists -> {s["id"]}')
                return s['id']
    model = embedding_model(route)
    code, resp = call(route, '/v1/vector_stores', 'POST',
                      {'name': name, 'embedding_model': model})
    if code not in (200, 201):
        sys.exit(f'  FAILED to create vector store: HTTP {code} {resp}')
    print(f'  created vector store "{name}" -> {resp["id"]}  (embedding: {model})')
    return resp['id']


def attach(route: str, store_id: str, file_id: str) -> bool:
    code, resp = call(route, f'/v1/vector_stores/{store_id}/files', 'POST',
                      {'file_id': file_id})
    if code not in (200, 201):
        print(f'    attach failed: HTTP {code} {str(resp)[:200]}')
        return False
    return True


def ingest(route: str, store_id: str, paths: list[Path]) -> int:
    n = 0
    for p in paths:
        fid = upload_file(route, p)
        if attach(route, store_id, fid):
            print(f'  {p.name} -> {fid}')
            n += 1
    print(f'  ingested {n}/{len(paths)} file(s) into {store_id}')
    return n


def search(route: str, store_id: str, q: str, k: int = 3) -> None:
    code, resp = call(route, f'/v1/vector_stores/{store_id}/search', 'POST',
                      {'query': q, 'max_num_results': k})
    if code != 200:
        sys.exit(f'  FAILED search: HTTP {code} {resp}')
    hits = (resp or {}).get('data', [])
    print(f'  {len(hits)} hit(s) for {q!r}')
    for h in hits:
        chunks = h.get('content') or []
        text = ' '.join(c.get('text', '') for c in chunks if isinstance(c, dict))
        print(f'   - score={h.get("score"):.3f} {h.get("filename", "?")}: {text[:170]}')


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--route', required=True, help='https://llamastack-<ns>.apps...')
    ap.add_argument('--name', default='patch_history', help='vector store name')
    ap.add_argument('--dir', help='directory of files to ingest')
    ap.add_argument('--file', action='append', default=[], help='file to ingest (repeatable)')
    ap.add_argument('--query', help='search instead of ingesting')
    ap.add_argument('--list', action='store_true', help='list vector stores and exit')
    args = ap.parse_args()

    code, health = call(args.route, '/v1/health', timeout=30)
    if code != 200:
        sys.exit(f'Llama Stack not reachable at {args.route}: HTTP {code} {health}')
    print(f'Llama Stack healthy at {args.route}')

    if args.list:
        _, resp = call(args.route, '/v1/vector_stores', timeout=60)
        for s in (resp or {}).get('data', []):
            print(f'  {s["id"]}  {s.get("name")}  files={s.get("file_counts", {}).get("total")}')
        return

    store_id = find_or_create_store(args.route, args.name)

    if args.query:
        search(args.route, store_id, args.query)
        return

    paths = [Path(f) for f in args.file]
    if args.dir:
        paths += sorted(p for p in Path(args.dir).rglob('*')
                        if p.is_file() and p.suffix in TEXT_SUFFIXES)
    if not paths:
        sys.exit('Nothing to ingest — pass --dir or --file (or use --query / --list)')

    ingest(args.route, store_id, paths)
    print()
    print(f'  Set this for the console:  VECTOR_DB_ID={store_id}')


if __name__ == '__main__':
    main()
