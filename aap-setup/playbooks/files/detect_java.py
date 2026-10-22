#!/usr/bin/env python3
"""
Work out which JDK a checked-out repository needs.

    detect_java.py --root DIR

Looks at every pom.xml in the tree (compiler release/source/target, java.version, the enforcer's requireJavaVersion, a
Spring Boot parent) and at version pins (.java-version, .sdkmanrc, .tool-versions). The highest requirement found wins,
because a JDK older than the source level never compiles it. With nothing like that, a GitHub Actions java-version or a
Dockerfile base image is used as a hint. With nothing at all the answer is the default.

The answer is rounded up to a long-term-support release (8, 11, 17, 21), the ones a JDK can be fetched for.

Prints one JSON object on stdout: version, declared (what the files asked for), reason, and the evidence behind it.
Standard library only, because it runs on a build host that has nothing else.
"""
import argparse
import json
import re
import sys
from pathlib import Path

LTS = (8, 11, 17, 21)
DEFAULT = 17
SKIP = {'.git', 'target', 'node_modules', 'build', '.venv', 'venv'}
MAX_POMS = 200

_TAG = r'<%s>\s*([^<]*?)\s*</%s>'


def tag(text, name):
    m = re.search(_TAG % (re.escape(name), re.escape(name)), text)
    return m.group(1) if m else None


def major(value):
    """'1.8' -> 8, '17' -> 17, '11.0.2' -> 11, '[17,)' -> 17. None when it is not a Java version."""
    if value is None:
        return None
    m = re.search(r'(\d+)(?:\.(\d+))?', value)
    if not m:
        return None
    n = int(m.group(1))
    if n == 1 and m.group(2):
        n = int(m.group(2))
    return n if 5 <= n <= 60 else None


def properties(text):
    block = re.search(r'<properties>(.*?)</properties>', text, re.S)
    return dict(re.findall(r'<([\w.\-]+)>\s*([^<]*?)\s*</\1>', block.group(1))) if block else {}


def resolve(value, props):
    for _ in range(4):
        m = re.fullmatch(r'\$\{([^}]+)\}', value or '')
        if not m:
            break
        value = props.get(m.group(1))
    return value


def from_pom(rel, text):
    props = properties(text)
    found = []
    for key in ('maven.compiler.release', 'maven.compiler.target', 'maven.compiler.source', 'java.version'):
        value = resolve(props.get(key), props)
        if major(value):
            found.append((rel, f'{key} {value}', major(value)))
    for plugin in re.findall(r'<plugin>.*?</plugin>', text, re.S):
        if 'maven-compiler-plugin' in plugin:
            for key in ('release', 'target', 'source'):
                raw = resolve(tag(plugin, key), props)
                if major(raw):
                    found.append((rel, f'maven-compiler-plugin {key} {raw}', major(raw)))
        if 'maven-enforcer-plugin' in plugin:
            m = re.search(r'<requireJavaVersion>.*?<version>\s*([^<]*?)\s*</version>', plugin, re.S)
            if m and major(m.group(1)):
                found.append((rel, f'enforcer requireJavaVersion {m.group(1)}', major(m.group(1))))
    parent = re.search(r'<parent>(.*?)</parent>', text, re.S)
    if parent and tag(parent.group(1), 'artifactId') == 'spring-boot-starter-parent':
        boot = re.match(r'\d+', tag(parent.group(1), 'version') or '')
        if boot:
            need = 17 if int(boot.group()) >= 3 else 8
            found.append((rel, f'parent spring-boot-starter-parent {tag(parent.group(1), "version")}', need))
    return found


def from_pins(root):
    found = []
    for name, pattern in (('.java-version', r'(\d+(?:\.\d+)*)'), ('.sdkmanrc', r'^java\s*=\s*(\d+(?:\.\d+)*)'),
                          ('.tool-versions', r'^(?:java|openjdk)\s+(?:[a-z]+-)?(?:openjdk-)?(\d+(?:\.\d+)*)')):
        path = root / name
        if path.is_file():
            m = re.search(pattern, path.read_text(errors='replace'), re.M | re.I)
            if m and major(m.group(1)):
                found.append((name, f'{name} {m.group(1)}', major(m.group(1))))
    return found


def hints(root):
    found = []
    flows = root / '.github' / 'workflows'
    if flows.is_dir():
        for f in sorted(flows.glob('*.y*ml'))[:20]:
            m = re.search(r'java-version:\s*[\'"]?(\d+(?:\.\d+)*)', f.read_text(errors='replace'))
            if m and major(m.group(1)):
                found.append((f'.github/workflows/{f.name}', f'java-version {m.group(1)}', major(m.group(1))))
    for f in [root / 'Dockerfile'] + sorted(root.glob('*/Dockerfile'))[:5]:
        if f.is_file():
            m = re.search(r'^FROM\s+\S*(?:openjdk|temurin|corretto|jdk|maven)\S*?:(?:\S*?-)?(\d+)', f.read_text(errors='replace'), re.M | re.I)
            if m and major(m.group(1)):
                found.append((str(f.relative_to(root)), f'base image Java {m.group(1)}', major(m.group(1))))
    return found


def poms(root):
    out = []
    for path in sorted(root.rglob('pom.xml')):
        if SKIP.isdisjoint(path.relative_to(root).parts[:-1]):
            out.append(path)
        if len(out) >= MAX_POMS:
            break
    return out


def detect(root):
    root = Path(root)
    strong = from_pins(root)
    for path in poms(root):
        strong += from_pom(str(path.relative_to(root)), path.read_text(errors='replace'))
    weak = [] if strong else hints(root)
    evidence = strong or weak
    if evidence:
        declared = max(v for _, _, v in evidence)
        decider = next(e for e in evidence if e[2] == declared)
        reason = f'{decider[0]}: {decider[1]}'
        if not strong:
            reason += ' (a hint, not a requirement)'
    else:
        declared, reason = None, 'nothing in the repository says, so the default'
    want = declared if declared else DEFAULT
    version = next((n for n in LTS if n >= want), LTS[-1])
    if declared and declared > LTS[-1]:
        reason += f'; Java {declared} is newer than the {LTS[-1]} this job can fetch, so it may not compile'
    return {'version': version, 'declared': declared, 'reason': reason,
            'evidence': [{'file': f, 'what': w, 'java': v} for f, w, v in evidence[:10]]}


def main():
    ap = argparse.ArgumentParser(description='Work out which JDK a repository needs.')
    ap.add_argument('--root', required=True)
    args = ap.parse_args()
    print(json.dumps(detect(args.root)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
