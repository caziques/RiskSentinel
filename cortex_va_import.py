#!/usr/bin/env python3
"""
Palo Alto Cortex (legacy VA model) -> RiskSentinel importer.

For tenants whose vulnerability data sits in the legacy `va_cves` dataset rather
than the new-platform `findings` dataset. Built for the MotusCR tenant, which is
mid-migration from the older MCR tenant: same new platform and XDM schema, but
`findings` is still empty while `va_cves` is populated.

READ THIS BEFORE USING IT ELSEWHERE. On the old MCR tenant both datasets were
populated and they did NOT agree: `va_cves` was internally consistent and
freshly calculated, yet understated the real position by roughly 70% and
attributed findings to hosts the console reported as clean. `findings` is
authoritative wherever it has data. Use this importer only where `findings` is
empty, and move to cortex_import.py as soon as it populates.

Shape of the data, which differs from cortex_import.py in ways that matter:
  * va_cves is CVE-grain. One row carries `affected_hosts`, an array of host
    names, which this expands into one RiskSentinel finding per host.
  * There is no package identifier and no CVSS vector, only `severity` and
    `severity_score`, so per-host software detail is simply not available.
  * `is_excluded` marks CVEs the tenant has dismissed; those are imported as
    suppressed rather than dropped, so they stay visible for review.

Exclusions: prefer --exclude-types for whole classes of machine. A group-based
rule depends on the rollout naming its groups consistently, and a new group of
workstations would import silently; a type-based rule cannot miss them.

Usage:
    python3 cortex_va_import.py --env-file .env.cortex.motuscr --customer MotusCR
    python3 cortex_va_import.py --env-file .env.cortex.motuscr --customer MotusCR --dry-run

Credentials (env or --env-file):
    CORTEX_BASE_URL     https://api-<tenant>.xdr.<region>.paloaltonetworks.com
    CORTEX_API_KEY_ID   the integer sent as x-xdr-auth-id
    CORTEX_API_KEY      the key itself (Standard security level)
"""

import argparse
import gzip
import json
import os
import ssl
import sys
import time
import urllib.request
import urllib.error
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

_SSL_CTX = ssl.create_default_context()

PAGE_SIZE = 1000
# Over PAGE_SIZE, Cortex returns a stream_id instead of rows and the whole set
# is fetched in one go. Same mechanism cortex_import.py uses.
STREAM_LIMIT = 500000

sys.path.insert(0, str(Path(__file__).parent))
from app import app, db, resolve_severity, SEV_LEVEL, apply_suppression_rules
from models import ScanImport, Vulnerability

BASE_URL = API_KEY_ID = API_KEY = None

# Legacy severities are upper case; RiskSentinel stores title case.
SEV_MAP = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
           "LOW": "Low", "INFORMATIONAL": "Informational", "NONE": "Informational"}

TYPE_MAP = {"OPERATING_SYSTEM": "Operating System",
            "APPLICATION": "Application",
            "APPLICATION_AND_OS": "Application and OS"}


def _load_env(path: Path, override: bool = False) -> bool:
    if not path.exists():
        return False
    for raw in path.read_text().splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        k, v = raw.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if override or k not in os.environ:
            os.environ[k] = v
    return True


_BUSY = "parallel running queries"


def _post(path, body, timeout=300, attempts=8):
    data = json.dumps(body).encode()
    for attempt in range(attempts):
        req = urllib.request.Request(BASE_URL.rstrip("/") + path, data=data,
                                     headers={"x-xdr-auth-id": str(API_KEY_ID),
                                              "Authorization": API_KEY,
                                              "Content-Type": "application/json"},
                                     method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            detail = e.read()[:400].decode(errors="replace")
            transient = e.code in (429, 500, 502, 503) and (
                _BUSY in detail or e.code in (429, 502, 503))
            if transient and attempt < attempts - 1:
                time.sleep(min(2 ** attempt, 30))
                continue
            raise SystemExit(f"ERROR: Cortex API {e.code} on {path}\n  {detail}")
        except (urllib.error.URLError, TimeoutError):
            if attempt < attempts - 1:
                time.sleep(min(2 ** attempt, 30))
                continue
            raise
    raise SystemExit("ERROR: exhausted retries against the Cortex API")


def _run_query(query, days, limit):
    started = _post("/public_api/v1/xql/start_xql_query/",
                    {"request_data": {"query": query, "tenants": [],
                                      "timeframe": {"relativeTime": int(days * 86400000)}}})
    qid = started.get("reply")
    for _ in range(900):
        rep = _post("/public_api/v1/xql/get_query_results/",
                    {"request_data": {"query_id": qid, "pending_flag": True,
                                      "limit": limit, "format": "json"}}).get("reply") or {}
        status = rep.get("status")
        if status in ("SUCCESS", "PARTIAL_SUCCESS"):
            return rep
        if status == "FAIL":
            raise SystemExit(f"ERROR: XQL failed: {str(rep.get('error') or rep)[:300]}")
        time.sleep(0.4)
    raise SystemExit("ERROR: timed out waiting for XQL results")


def xql(query, days=1, limit=PAGE_SIZE):
    rep = _run_query(query, days, limit)
    return (rep.get("results") or {}).get("data") or []


def xql_stream(query, days=1, progress=None):
    """Every row of a result set in one query, via the stream endpoint."""
    rep = _run_query(query, days, STREAM_LIMIT)
    results = rep.get("results") or {}
    if results.get("data") is not None and not results.get("stream_id"):
        return results["data"] or []
    stream_id = results.get("stream_id")
    if not stream_id:
        return []
    expected = rep.get("number_of_results") or 0
    cost = list((rep.get("query_cost_charged") or {}).values())
    if progress:
        progress(f"  streaming {expected:,} rows in one query "
                 f"(cost {(cost[0] if cost else 0):.4f})")

    body = json.dumps({"request_data": {"stream_id": stream_id,
                                        "is_gzip_compressed": True}}).encode()
    req = urllib.request.Request(
        BASE_URL.rstrip("/") + "/public_api/v1/xql/get_query_results_stream/",
        data=body,
        headers={"x-xdr-auth-id": str(API_KEY_ID), "Authorization": API_KEY,
                 "Content-Type": "application/json", "Accept-Encoding": "gzip"},
        method="POST")
    with urllib.request.urlopen(req, timeout=1800, context=_SSL_CTX) as r:
        raw = r.read()
    # Gzipped by the stream and again by the transport.
    while raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    rows = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    if expected and len(rows) != expected:
        print(f"  WARNING: stream returned {len(rows):,} rows, "
              f"Cortex said {expected:,}", flush=True)
    return rows


def ms_to_dt(ms):
    if not ms:
        return None
    try:
        return datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc).replace(tzinfo=None)
    except (TypeError, ValueError, OSError):
        return None


TYPE_LABEL = {"TYPE_SERVER": "Server", "TYPE_WORKSTATION": "Workstation",
              "TYPE_MOBILE": "Mobile", "TYPE_CONTAINER": "Container"}


def fetch_endpoints(days):
    """
    endpoint name -> {groups, type, ip, os, platform, internet_facing}.

    One query against the `endpoints` dataset, which carries group membership,
    asset type, IP addresses, OS and network location. va_cves carries none of
    those, and the `findings` dataset has no IP either, so this is the only
    place the portal can get them for a Cortex tenant.

    Host names here match va_cves.affected_hosts exactly, verified on this
    tenant for all 269 hosts. Matching on anything else would enrich nothing.
    """
    out = {}
    try:
        rows = xql_stream(
            "dataset = endpoints | fields endpoint_name, endpoint_type, "
            "group_names, ip_address, operating_system, platform, "
            "network_location", days)
    except (SystemExit, urllib.error.URLError, TimeoutError):
        return out
    for r in rows:
        name = (r.get("endpoint_name") or "").strip()
        if not name:
            continue
        groups = r.get("group_names") or []
        if isinstance(groups, str):
            groups = [groups]
        ips = r.get("ip_address") or []
        if isinstance(ips, str):
            ips = [ips]
        loc = (r.get("network_location") or "").upper()
        out[name] = dict(
            groups={str(g).strip() for g in groups if str(g).strip()},
            type=TYPE_LABEL.get(r.get("endpoint_type") or "",
                                (r.get("endpoint_type") or "").replace("TYPE_", "").title()),
            ip=", ".join(str(i) for i in ips)[:64],
            os=(r.get("operating_system") or "").strip(),
            platform=(r.get("platform") or "").strip(),
            internet_facing=loc.endswith("EXTERNAL"),
        )
    return out


def fetch_asset_ips(days):
    """Asset name -> IP string, best effort."""
    out = {}
    try:
        rows = xql_stream("dataset = asset_inventory | fields xdm.asset.id, "
                          "xdm.asset.name, xdm.asset.normalized_fields", days)
    except (SystemExit, urllib.error.URLError, TimeoutError):
        return out
    for r in rows:
        name = r.get("xdm.asset.name")
        if not name:
            continue
        nf = r.get("xdm.asset.normalized_fields") or {}
        ips = (nf.get("xdm.host.ipv4_addresses")
               or nf.get("xdm.asset.ipv4_addresses") or [])
        if isinstance(ips, str):
            ips = [ips]
        if ips:
            out[name] = ", ".join(str(i) for i in ips)[:64]
    return out


def prior_first_seen(customer_id):
    """Earliest first_seen already recorded per (asset, CVE) for this customer."""
    from sqlalchemy import func
    rows = (db.session.query(Vulnerability.asset, Vulnerability.vulnerability_id,
                             func.min(Vulnerability.first_seen))
            .join(ScanImport, Vulnerability.scan_import_id == ScanImport.id)
            .filter(ScanImport.customer_id == customer_id,
                    Vulnerability.first_seen.isnot(None))
            .group_by(Vulnerability.asset, Vulnerability.vulnerability_id)
            .all())
    return {(a, v): fs for a, v, fs in rows}


def expand_record(r, host, ips, carried, now, endpoints=None):
    """One va_cves row plus one of its affected hosts -> one RiskSentinel finding."""
    cve = (r.get("name") or "").strip()
    host = (host or "").strip()
    if not cve or not host:
        return None

    try:
        score = float(r.get("severity_score"))
    except (TypeError, ValueError):
        score = None
    sev_text = SEV_MAP.get((r.get("severity") or "").upper())
    risk = resolve_severity(None, sev_text, score, None)

    products = r.get("affected_products") or []
    if isinstance(products, str):
        products = [products]
    software = ", ".join(str(p) for p in products)[:500] or None

    os_types = r.get("os_type") or []
    if isinstance(os_types, str):
        os_types = [os_types]

    published = ms_to_dt(r.get("publication_date"))
    modified  = ms_to_dt(r.get("modification_date"))
    # va_cves has no per-host first-seen, so carry forward what we already know
    # and fall back to the CVE's publication date rather than inventing today.
    first_seen = carried.get((host, cve), published or modified or now)

    labels = []
    for key, tag in (("exploitability_score", "exploitability"),
                     ("impact_score", "impact")):
        v = r.get(key)
        if isinstance(v, (int, float)) and v:
            labels.append(f"{tag}={v}")
    if (r.get("is_excluded") or "").upper() == "YES":
        labels.append("excluded-in-cortex")

    # Enrichment from the `endpoints` dataset. va_cves describes the CVE; the
    # host's type, address and exposure only exist over there.
    ep = (endpoints or {}).get(host) or {}
    if ep.get("type"):
        labels.append(f"type={ep['type']}")
    if ep.get("internet_facing"):
        labels.append("internet-facing")

    # A CVE the tenant has dismissed is imported suppressed rather than dropped,
    # so the decision stays visible and reviewable here too.
    excluded = (r.get("is_excluded") or "").upper() == "YES"

    return dict(
        vulnerability_id = cve,
        suppressed       = excluded,
        suppression_reason = ("Excluded in Cortex" if excluded else None),
        asset            = host,
        # endpoints carries real addresses; asset_inventory does not resolve for
        # these hosts, which is why this column was empty for Cortex tenants.
        ip_address       = (ep.get("ip") or ips.get(host, "") or ""),
        source           = "cortex-va",
        labels           = ", ".join(labels)[:500],
        first_seen       = first_seen,
        last_seen        = modified or now,
        cvss_v3_severity = sev_text,
        cvss_v3_score    = score,
        cvss_v4_severity = None,
        cvss_v4_score    = None,
        available_patches= None,
        affected_software= software,
        plugin_id        = cve,
        plugin_name      = cve,
        plugin_family    = TYPE_MAP.get(r.get("type") or "", r.get("type") or ""),
        risk_factor      = risk,
        severity_level   = SEV_LEVEL.get(risk, 0),
        synopsis         = (software or cve)[:500],
        description      = (r.get("description") or ""),
        solution         = "",
        port             = "",
        protocol         = "",
        plugin_output    = (ep.get("os")
                            or " ".join(str(x) for x in os_types)),
        cpe              = "",
    )


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--days", type=int, default=int(os.environ.get("CORTEX_DAYS", "30")),
                   help="XQL lookback window in days (va_cves is current-state; default 30)")
    p.add_argument("--notes", default="")
    p.add_argument("--customer", default=os.environ.get("PORTAL_CUSTOMER", ""))
    p.add_argument("--env-file", default="")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--exclude-groups", default="",
                   help="comma-separated Cortex endpoint groups to leave out, "
                        "e.g. \"EC WORKSTATIONS\". Matched case-insensitively.")
    p.add_argument("--exclude-types", default="",
                   help="comma-separated Cortex endpoint types to leave out, "
                        "e.g. WORKSTATION. Prefer this over --exclude-groups for "
                        "whole classes of machine: it does not depend on how the "
                        "rollout happens to name its groups.")
    args = p.parse_args()

    global BASE_URL, API_KEY_ID, API_KEY
    if args.env_file:
        if not _load_env(Path(args.env_file), override=True):
            raise SystemExit(f"ERROR: --env-file not found: {args.env_file}")
    else:
        _load_env(Path(__file__).with_name(".env"))
    BASE_URL   = os.environ.get("CORTEX_BASE_URL", "").rstrip("/")
    API_KEY_ID = os.environ.get("CORTEX_API_KEY_ID", "")
    API_KEY    = os.environ.get("CORTEX_API_KEY", "")
    if not (BASE_URL and API_KEY and API_KEY_ID):
        raise SystemExit("ERROR: CORTEX_BASE_URL / CORTEX_API_KEY_ID / CORTEX_API_KEY not set.")

    cust_name = (args.customer or "").strip() or "Default"
    with app.app_context():
        from models import Customer
        customer = Customer.query.filter_by(name=cust_name).first()
        if not customer:
            raise SystemExit(f"ERROR: Customer '{cust_name}' not found in database.")
        cust_id = customer.id
        carried = prior_first_seen(cust_id)

    print(f"Tenant: {BASE_URL}")
    print("Source: va_cves dataset (legacy VA model)", flush=True)

    # If findings has data, this importer is the wrong one. Say so loudly rather
    # than quietly producing numbers that disagree with the console.
    try:
        probe = xql(f'dataset = findings | filter xdm.finding.category = "VULNERABILITY" '
                    f'and xdm.finding.is_active = true | comp count() as n', args.days)
        n_findings = int((probe[0].get("n") if probe else 0) or 0)
    except SystemExit:
        n_findings = 0
    if n_findings:
        print(f"\n  WARNING: this tenant's `findings` dataset now holds "
              f"{n_findings:,} active vulnerability findings.")
        print("  `findings` is authoritative where it has data. Use cortex_import.py")
        print("  instead; this legacy importer will understate the real position.\n",
              flush=True)

    expected = 0
    rows_count = xql("dataset = va_cves | comp count() as n", args.days)
    if rows_count:
        expected = int(rows_count[0].get("n") or 0)
    print(f"Cortex reports {expected:,} CVEs in va_cves", flush=True)
    if carried:
        print(f"  carrying first_seen forward for {len(carried):,} known findings",
              flush=True)

    # Group exclusions and enrichment both come from `endpoints`. va_cves has no
    # notion of groups, IPs or asset type, so hosts are filtered and enriched as
    # the CVE rows are expanded.
    print("Fetching endpoint detail (type, groups, IP, OS, exposure)...", flush=True)
    endpoints = fetch_endpoints(args.days)
    if endpoints:
        n_ip = sum(1 for e in endpoints.values() if e.get("ip"))
        types = Counter(e.get("type") or "?" for e in endpoints.values())
        ext = sum(1 for e in endpoints.values() if e.get("internet_facing"))
        print(f"  {len(endpoints)} endpoints: "
              + ", ".join(f"{n} {t}" for t, n in types.most_common())
              + f"; {n_ip} with an IP; {ext} internet-facing", flush=True)
    else:
        print("  WARNING: no endpoint detail available; findings will carry no "
              "type or exposure", flush=True)

    # asset_inventory is consulted only when `endpoints` yielded no addresses.
    # It does not resolve for these hosts, so querying it as well is wasted work.
    ips = {}
    if not any(e.get("ip") for e in endpoints.values()):
        print("Falling back to asset_inventory for IPs...", flush=True)
        ips = fetch_asset_ips(args.days)
        print(f"  {len(ips)} assets with IP data", flush=True)

    excluded_names = [g.strip() for g in args.exclude_groups.split(",") if g.strip()]
    excluded_types = [t.strip() for t in args.exclude_types.split(",") if t.strip()]
    excluded_hosts = set()

    if (excluded_names or excluded_types) and not endpoints:
        raise SystemExit("ERROR: could not read endpoint detail, so the exclusions "
                         "cannot be applied. Refusing to import everything silently.")

    if excluded_types:
        # Type is a property of the machine, so this keeps working however the
        # rollout chooses to name or organise its groups. Matched against both
        # the raw value and the friendly label, so WORKSTATION and
        # TYPE_WORKSTATION both work.
        wanted = {t.upper().replace("TYPE_", "") for t in excluded_types}
        print(f"Excluding type(s): {', '.join(excluded_types)}", flush=True)
        hit = {h for h, i in endpoints.items()
               if (i.get("type") or "").upper() in wanted}
        excluded_hosts |= hit
        print(f"  {len(hit)} endpoint(s) of that type", flush=True)
        present = {(i.get("type") or "").upper() for i in endpoints.values()}
        unmatched = wanted - present
        if unmatched:
            print(f"  WARNING: no endpoint has type: {', '.join(sorted(unmatched))}"
                  f"  (seen: {', '.join(sorted(x for x in present if x))})", flush=True)

    if excluded_names:
        wanted = {g.upper() for g in excluded_names}
        print(f"Excluding group(s): {', '.join(excluded_names)}", flush=True)
        hit = {h for h, i in endpoints.items()
               if {g.upper() for g in i["groups"]} & wanted}
        excluded_hosts |= hit
        print(f"  {len(hit)} endpoint(s) in the excluded group(s)", flush=True)
        unmatched = wanted - {g.upper() for i in endpoints.values() for g in i["groups"]}
        if unmatched:
            # A typo here would silently exclude nothing, so name it.
            print(f"  WARNING: no endpoint belongs to: {', '.join(sorted(unmatched))}",
                  flush=True)

    if excluded_hosts:
        print(f"  {len(excluded_hosts)} host(s) excluded in total", flush=True)

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    print("Fetching CVEs in a single streamed query...", flush=True)
    cves = xql_stream("dataset = va_cves", args.days,
                      progress=lambda m: print(m, flush=True))

    records, seen = [], set()
    no_hosts = excluded_pairs = 0
    for r in cves:
        hosts = r.get("affected_hosts") or []
        if isinstance(hosts, str):
            hosts = [hosts]
        if not hosts:
            no_hosts += 1
            continue
        for h in hosts:
            host = str(h).strip()
            if host in excluded_hosts:
                excluded_pairs += 1
                continue
            key = (host, (r.get("name") or "").strip())
            if key in seen:
                continue
            seen.add(key)
            rec = expand_record(r, h, ips, carried, now, endpoints)
            if rec:
                records.append(rec)

    print(f"\nExpanded {len(cves):,} CVEs into {len(records):,} host findings")
    if excluded_pairs:
        print(f"  {excluded_pairs:,} finding(s) left out, on "
              f"{len(excluded_hosts)} excluded host(s)")
    if no_hosts:
        print(f"  {no_hosts:,} CVE(s) listed no affected host and were skipped")
    if expected and len(cves) != expected:
        print(f"  WARNING: fetched {len(cves):,} CVEs, Cortex reported {expected:,}")

    if not records:
        print("Nothing to import.")
        return

    sev = Counter(r["risk_factor"] for r in records)
    print("\nSeverity breakdown:")
    for s, n in sorted(sev.items(), key=lambda x: -SEV_LEVEL.get(x[0], 0)):
        print(f"  {s:14} {n:>8,}")
    supp = sum(1 for r in records if r["suppressed"])
    if supp:
        print(f"  ({supp:,} imported suppressed, excluded in Cortex)")

    with_ip = sum(1 for r in records if r["ip_address"])
    typed   = Counter()
    for r in records:
        for t in (r["labels"] or "").split(","):
            t = t.strip()
            if t.startswith("type="):
                typed[t[5:]] += 1
    print(f"\nEnrichment: {with_ip:,} finding(s) with an IP"
          + (f"; by asset type " + ", ".join(f"{n:,} {t}" for t, n in typed.most_common())
             if typed else ""))

    hosts = Counter(r["asset"] for r in records)
    print(f"Affected assets: {len(hosts):,}")
    for h, n in hosts.most_common(10):
        print(f"  {n:>7,}  {h}")

    if args.dry_run:
        print("\n--dry-run: nothing written to the database.")
        return

    print("\nWriting to database...", flush=True)
    with app.app_context():
        from models import Customer
        customer = Customer.query.filter_by(name=cust_name).first()
        print(f"  Importing into customer: {customer.name}", flush=True)
        scan_name = f"Cortex-VA-{now.strftime('%Y-%m-%d')}.api"
        scan = ScanImport(filename=scan_name, report_date=now.date(),
                          customer_id=customer.id, imported_by_id=None,
                          notes=args.notes or "Automated Cortex import (va_cves dataset)")
        db.session.add(scan)
        db.session.flush()
        CHUNK = 5000
        for i in range(0, len(records), CHUNK):
            db.session.bulk_save_objects([
                Vulnerability(scan_import_id=scan.id, **r) for r in records[i:i + CHUNK]])
            db.session.flush()
        scan.record_count = len(records)
        db.session.commit()

        n = apply_suppression_rules(customer.id, scan.id)
        if n:
            print(f"  Re-applied suppression rules to {n:,} finding(s)", flush=True)
    print(f"Done, imported {len(records):,} findings as '{scan_name}'")


if __name__ == "__main__":
    main()
