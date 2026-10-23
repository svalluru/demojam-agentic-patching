#!/usr/bin/env python3
"""Find the Insights identity of the hosts AAP can actually patch.

Everything that identifies a host is rebuilt with the cluster. A new lab
gives new Insights UUIDs, new display names (the sandbox id is in the FQDN)
and a new group tag value. Pinning any of them in .env means .env is wrong
the morning after a rebuild, and wrong in the quiet way: the console still
starts, the CVE list still loads, and the first assessment fails on a host
that no longer exists.

Two things do survive a rebuild, so discovery starts from them:

  the AAP inventory names   node1, node2, node3 — chosen by the lab, not
                            generated, and the names AAP patches by
  the tag key               insights-client/group — only the value moves

So: ask AAP which hosts it can reach, find each one in Insights, and read
the identities back off the answer rather than carrying them forward.

  ./discover-hosts.py                       report what is there
  ./discover-hosts.py --write               scope .env to all of them (HOSTS_TAG)
  ./discover-hosts.py --host node1 --write  ...and pin one (HOSTS_FILTER)
  ./discover-hosts.py --inventory X         a different AAP inventory

Run it after any cluster rebuild. Every identifier it writes is one that
the rebuild changed, which is the whole reason not to type them by hand.

Standard library only, like the rest of the repo. Honours
INSIGHTS_VERIFY_TLS / AAP_VERIFY_TLS from .env.
"""
import argparse
import json
import os
import pathlib
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent
SSO = ('https://sso.redhat.com/auth/realms/redhat-external'
       '/protocol/openid-connect/token')
INSIGHTS = 'https://console.redhat.com/api'


def load_env(path):
    env = {}
    if not path.exists():
        sys.exit(f'error: {path} not found')
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, v = line.split('=', 1)
        env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def ctx_for(env, key):
    ctx = ssl.create_default_context()
    if env.get(key, 'true').lower() in ('0', 'false', 'no'):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def get_json(url, headers, ctx, timeout=90):
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            return json.loads(r.read() or b'{}'), r.status
    except urllib.error.HTTPError as e:
        return None, e.code
    except Exception as e:
        return {'_transport': str(e)[:120]}, 0


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument('--inventory', default=os.environ.get('TARGET_INVENTORY',
                                                          'lab-inventory'))
    ap.add_argument('--env-file', default=str(ROOT / '.env'))
    ap.add_argument('--host', default='',
                    help='the host to target; with --write, pins HOSTS_FILTER '
                         'to its uuid')
    ap.add_argument('--write', action='store_true',
                    help='write the values back to .env')
    args = ap.parse_args()

    env_path = pathlib.Path(args.env_file)
    env = load_env(env_path)
    for key in ('AAP_BASE_URL', 'AAP_TOKEN',
                'LIGHTSPEED_CLIENT_ID', 'LIGHTSPEED_CLIENT_SECRET'):
        if not env.get(key):
            sys.exit(f'error: {key} is empty in {env_path}')

    # -- AAP: which hosts can actually be patched -------------------------
    actx = ctx_for(env, 'AAP_VERIFY_TLS')
    ah = {'Authorization': f"Bearer {env['AAP_TOKEN']}"}
    base = env['AAP_BASE_URL'].rstrip('/')
    inv, code = get_json(
        f'{base}/inventories/?name={urllib.parse.quote(args.inventory)}',
        ah, actx)
    # Distinguish "AAP said no" from "never reached AAP". Reporting a
    # transport failure as "inventory not found" sends you looking in the
    # controller UI for something that is sitting there perfectly fine.
    if code == 0:
        why = (inv or {}).get('_transport', 'unknown')
        hint = ('set AAP_VERIFY_TLS=false in .env' if 'CERTIFICATE' in why.upper()
                else 'check AAP_BASE_URL and that the controller is up')
        sys.exit(f'error: could not reach AAP — {why}\n       {hint}')
    rows = (inv or {}).get('results') or []
    if code != 200:
        sys.exit(f'error: AAP returned HTTP {code} '
                 f'({"check AAP_TOKEN" if code == 401 else "controller may be restarting"})')
    if not rows:
        sys.exit(f'error: AAP has no inventory named {args.inventory!r} — '
                 f'pass --inventory')
    inv_id = rows[0]['id']
    hosts, code = get_json(f'{base}/inventories/{inv_id}/hosts/?page_size=200',
                           ah, actx)
    aap_names = [h['name'] for h in (hosts or {}).get('results', [])]
    if not aap_names:
        sys.exit(f'error: AAP inventory {args.inventory!r} has no hosts')
    print(f'AAP {args.inventory} ({len(aap_names)}): {", ".join(aap_names)}\n')

    # -- Insights ---------------------------------------------------------
    ictx = ctx_for(env, 'INSIGHTS_VERIFY_TLS')
    data = urllib.parse.urlencode({
        'grant_type': 'client_credentials',
        'client_id': env['LIGHTSPEED_CLIENT_ID'],
        'client_secret': env['LIGHTSPEED_CLIENT_SECRET'],
        'scope': 'api.console'}).encode()
    req = urllib.request.Request(
        SSO, data=data, method='POST',
        headers={'Content-Type': 'application/x-www-form-urlencoded'})
    try:
        with urllib.request.urlopen(req, context=ictx, timeout=45) as r:
            tok = json.loads(r.read())['access_token']
    except Exception as e:
        sys.exit(f'error: Insights SSO rejected the service account: {str(e)[:90]}')
    ih = {'Authorization': f'Bearer {tok}'}

    # Narrow Insights to this lab before matching anything by name.
    #
    # Everyone running this lab gets hosts called node1, node2 and node3, and
    # they all land in the same Insights organisation: 566 records match
    # 'node1', a hundred of them with exactly that first label, several
    # checking in within the same minute. Picking the most recent is picking
    # whoever rebooted last, and that is somebody else's machine.
    #
    # The lab id in AAP_BASE_URL is the one thing on hand that is certainly
    # yours — controller-h77wc… — and the hosts carry it as an
    # insights-client/group tag. That turns a search of hundreds into a set
    # of three.
    lab = re.search(r'//[a-z-]*?-([a-z0-9]{4,})\.', base)
    scoped, scope_tag = {}, ''
    if lab:
        scope_tag = f'insights-client/group={lab.group(1)}'
        j, _ = get_json(f'{INSIGHTS}/inventory/v1/hosts?per_page=100&tags='
                        f'{urllib.parse.quote(scope_tag)}', ih, ictx)
        for h in ((j or {}).get('results') or []):
            scoped.setdefault((h.get('display_name') or '').split('.')[0], h)
        print(f'scoped to {scope_tag} -> {len(scoped)} host(s)\n'
              if scoped else
              f'warning: {scope_tag} matched nothing; falling back to names\n')

    found, missing, ambiguous, tags_seen = [], [], [], {}
    for name in aap_names:
        h = scoped.get(name)
        if h is None:
            j, _ = get_json(f'{INSIGHTS}/inventory/v1/hosts'
                            f'?hostname_or_id={urllib.parse.quote(name)}', ih, ictx)
            cand = [x for x in ((j or {}).get('results') or [])
                    if (x.get('display_name') or '').split('.')[0] == name]
            if not cand:
                missing.append(name)
                continue
            if len(cand) > 1:
                # Refuse rather than guess. The uuid written here decides
                # which machine gets patched.
                ambiguous.append((name, cand))
                continue
            h = cand[0]
        t, _ = get_json(f"{INSIGHTS}/inventory/v1/hosts/{h['id']}/tags", ih, ictx)
        tl = ((t or {}).get('results') or {}).get(h['id']) or []
        grp = next((f"{x['namespace']}/{x['key']}={x['value']}" for x in tl
                    if x.get('key') == 'group'), '')
        if grp:
            tags_seen[grp] = tags_seen.get(grp, 0) + 1
        found.append((name, h.get('display_name'), h['id'], grp,
                      (h.get('updated') or '')[:19]))

    a = max([len(n) for n in aap_names] + [3])
    w = max([len(f[1] or '') for f in found] + [21])
    print(f"{'aap':<{a}} {'insights display_name':<{w}} {'uuid':<38} last check-in")
    print('-' * (a + w + 60))
    for name, dn, uuid, _grp, upd in found:
        print(f'{name:<{a}} {dn:<{w}} {uuid:<38} {upd}')
    for name in missing:
        print(f'{name:<{a}} {"NOT IN INSIGHTS":<{w}} '
              f'{"—":<38} register it, or it cannot be assessed')
    for name, cand in ambiguous:
        print(f'{name:<{a}} {"AMBIGUOUS":<{w}} {"—":<38} '
              f'{len(cand)} hosts share this name')

    if ambiguous:
        print('\nRefusing to choose between these. Everyone running this lab has a\n'
              'host of the same name in the same organisation, so the wrong pick\n'
              'patches a stranger\'s machine. Identify yours by its machine-id:\n'
              '\n    ssh <host> cat /etc/insights-client/machine-id\n'
              '\nthen find it with ?insights_id=<that>, or set HOSTS_FILTER to the\n'
              'uuid directly. Candidates:')
        for name, cand in ambiguous:
            for h in sorted(cand, key=lambda x: x.get('updated') or '',
                            reverse=True)[:5]:
                print(f"   {name}  {h['id']}  {h.get('display_name')}  "
                      f"insights_id={str(h.get('insights_id'))[:8]}…")
        return 1

    if not tags_seen:
        print('\nNo insights-client/group tag on these hosts. Select by uuid '
              '(HOSTS_FILTER) until they are tagged.')
        return 1 if missing else 0

    # The tag is only useful if it selects these hosts and nothing else —
    # a value shared with the rest of the estate is not a filter.
    tag = max(tags_seen, key=lambda k: tags_seen[k])
    j, _ = get_json(f'{INSIGHTS}/inventory/v1/hosts?per_page=1&tags='
                    f'{urllib.parse.quote(tag)}', ih, ictx)
    total = (j or {}).get('total')
    print(f'\ngroup tag : {tag}')
    print(f'            {tags_seen[tag]}/{len(found)} of these hosts carry it; '
          f'it selects {total} host(s) org-wide')
    exact = total == len(found) and tags_seen[tag] == len(found)
    print('            ' + ('exact match — safe as the host filter' if exact else
                            'does NOT match this set exactly; check before using it'))

    lab_tag = tag.split('/', 1)[1] if '/' in tag else tag
    write = {'LAB_TAG': lab_tag}

    # HOSTS_TAG is what the console scopes Insights by, and the reason to run
    # this at all. It used to be worked out, verified and printed, then left
    # out of what --write wrote, so the one value that matters most had to be
    # copied in by hand.
    #
    # Only when the tag selects exactly these hosts. One shared with the rest
    # of the organisation is not a filter, and writing it would scope the
    # console to other people's machines while looking configured.
    if exact:
        write['HOSTS_TAG'] = tag
    else:
        print('\nHOSTS_TAG not written: the tag does not select exactly these '
              'hosts. Set HOSTS_FILTER to a uuid above instead (--host).')

    # --host pins HOSTS_FILTER to that machine's uuid. The uuid rather than
    # the name because a display name is whatever the host last called
    # itself: these three have already flipped between 'node1' and
    # 'node1.sandbox-h77wc-ocp4-cluster.svc.cluster.local' and back within a
    # day, and the console resolves the filter against Insights, where a
    # partial name matches hundreds of other people's machines.
    if args.host:
        match = next((f for f in found if f[0] == args.host), None)
        if not match:
            print(f'\nerror: {args.host!r} is not in {args.inventory} — '
                  f'one of {", ".join(f[0] for f in found)}')
            return 1
        write['HOSTS_FILTER'] = match[2]

    print('\n.env:')
    for k, v in write.items():
        print(f'  {k}={v}')
    if not args.host:
        print('  HOSTS_FILTER=            # pass --host <name> to set this')

    if args.write:
        s = env_path.read_text()
        for k, v in write.items():
            pat = re.compile(rf'^{k}=.*$', re.M)
            s = pat.sub(f'{k}={v}', s) if pat.search(s) else s + f'\n{k}={v}\n'
        env_path.write_text(s)
        print(f'\nwrote {", ".join(write)} to {env_path}')
        if not args.host:
            print('HOSTS_FILTER left alone — empty means the console covers every '
                  'host HOSTS_TAG selects; pass --host to pin one.')
    return 1 if missing else 0


if __name__ == '__main__':
    sys.exit(main())
