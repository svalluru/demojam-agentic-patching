"""CVE intake — common code, not an agent.

Steps C1/C2 of the architecture: fetch the CVE list and resolve affected hosts
from Insights. Called by the console UI to populate the CVE table, and by the
Supervisor to load detail for the CVE being patched.

Kept out of the agent layer deliberately: there is no decision-making here, and
the UI needs it before any Supervisor exists.
"""
from __future__ import annotations

import logging
import os
from typing import Any

LOG = logging.getLogger('intake')


def fetch_cve_detail(cve_id: str) -> dict[str, Any]:
    """C1+C2 — CVE metadata and affected hosts.

    Returns ``{cvss, description, hosts, count, source}`` where source is
    'live' or 'fallback'. Never raises: a failed Insights call degrades to
    demo data so the console always has something to show.
    """
    import cve_flow_demo

    data, source = cve_flow_demo._try_fetch_cve(cve_id)
    hosts = _narrow(data['hosts'])
    return {
        'cvss': data['cvss'],
        'description': data['description'],
        'hosts': hosts,
        'count': len(hosts),
        'source': 'live' if source == 'LIVE' else 'fallback',
        'degraded': source != 'LIVE',
    }


def _narrow(hosts: list[dict]) -> list[dict]:
    """Optionally restrict the host set — for demos and local verification.

    HOSTS_FILTER=pay-app-07   keep only hosts whose name contains this
    HOSTS_LIMIT=1             keep at most this many

    Both unset means every affected host, which is the production behaviour.
    Worth knowing: the risk model is called once per host, so a 59-host CVE
    is 59 sequential round trips.
    """
    pattern = os.environ.get('HOSTS_FILTER', '').strip()
    if pattern:
        matched = [h for h in hosts if pattern in (h.get('host') or '')]
        if matched:
            hosts = matched
        else:
            LOG.warning('HOSTS_FILTER=%r matched no hosts; keeping all %d',
                        pattern, len(hosts))

    limit = os.environ.get('HOSTS_LIMIT', '').strip()
    if limit.isdigit() and int(limit) > 0:
        hosts = hosts[:int(limit)]
    return hosts


def fetch_cve_list(limit: int = 20, offset: int = 0) -> dict[str, Any]:
    """C1 — the paged CVE list behind the console's CVE table."""
    import cve_console

    return cve_console.fetch_cve_page(limit=limit, offset=offset)
