#!/usr/bin/env python3
"""
Apply a list of dependency version changes to a checked-out repository.

    apply_dependency_changes.py --root DIR --changes changes.json

changes.json is a list of {"name", "from", "to", "manifests": [paths]}. A Maven name is groupId:artifactId. Only a
version that is exactly the "from" value is changed, so a file that has moved on since the scan is left alone and
reported. Edits are made in place on the text, so the rest of the file keeps its formatting and comments.

Prints one JSON report on stdout: for each change, the files it was applied to and, when it was not, why.
Standard library only, because it runs on a build host that has nothing else.
"""
import argparse
import json
import re
import sys
from pathlib import Path

DEP = re.compile(r'<dependency>.*?</dependency>', re.S)


def _tag(block, tag):
    return re.search(r'<%s>\s*([^<]*?)\s*</%s>' % (tag, tag), block)


def edit_pom(text, name, old, new):
    """Returns (new text, how, reason). `how` says where the version was changed, or is empty with a reason."""
    group, _, artifact = name.partition(':')
    reason = 'no dependency %s in this file' % name
    for m in DEP.finditer(text):
        block = m.group(0)
        g, a, v = _tag(block, 'groupId'), _tag(block, 'artifactId'), _tag(block, 'version')
        if not (g and a and g.group(1) == group and a.group(1) == artifact):
            continue
        if not v:
            reason = 'the version is managed by a parent or BOM, so there is nothing here to change'
            continue
        found = v.group(1)
        prop = re.fullmatch(r'\$\{([^}]+)\}', found)
        if prop:
            key = prop.group(1)
            p = re.search(r'(<%s>\s*)([^<]*?)(\s*</%s>)' % (re.escape(key), re.escape(key)), text)
            if not p:
                reason = 'the version comes from property %s, which is not defined in this file' % key
                continue
            if p.group(2) != old:
                reason = 'property %s is %s, not %s' % (key, p.group(2), old)
                continue
            return text[:p.start(2)] + new + text[p.end(2):], 'property ' + key, ''
        if found != old:
            reason = 'the version here is %s, not %s' % (found, old)
            continue
        start = m.start() + v.start(1)
        return text[:start] + new + text[start + len(found):], 'version', ''
    return text, '', reason


def _norm(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def edit_requirements(text, name, old, new):
    lines = text.splitlines(keepends=True)
    rx = re.compile(r'^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?(\s*==\s*)([^\s;#\\]+)')
    reason = 'no pinned %s in this file' % name
    for i, line in enumerate(lines):
        m = rx.match(line)
        if not m or _norm(m.group(2)) != _norm(name):
            continue
        if m.group(5) != old:
            reason = 'the version here is %s, not %s' % (m.group(5), old)
            continue
        lines[i] = line[:m.start(5)] + new + line[m.end(5):]
        return ''.join(lines), 'version', ''
    return text, '', reason


def run(root, changes):
    root = Path(root).resolve()
    report = []
    for ch in changes:
        entry = {'name': ch['name'], 'from': ch['from'], 'to': ch['to'], 'applied': [], 'problems': []}
        for rel in ch['manifests']:
            path = (root / rel).resolve()
            if root not in path.parents or not path.is_file():
                entry['problems'].append('%s: not found' % rel)
                continue
            edit = edit_pom if path.name == 'pom.xml' else edit_requirements
            text = path.read_bytes().decode('utf-8')
            new_text, how, reason = edit(text, ch['name'], ch['from'], ch['to'])
            if how:
                path.write_bytes(new_text.encode('utf-8'))
                entry['applied'].append('%s (%s)' % (rel, how))
            else:
                entry['problems'].append('%s: %s' % (rel, reason))
        report.append(entry)
    return report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', required=True)
    ap.add_argument('--changes', required=True)
    args = ap.parse_args()
    report = run(args.root, json.loads(Path(args.changes).read_text()))
    json.dump(report, sys.stdout)
    print()
    return 0 if any(e['applied'] for e in report) else 1


if __name__ == '__main__':
    sys.exit(main())
