#!/usr/bin/env python3
"""
Palo Alto Cortex -> RiskSentinel direct importer.

Reads the `findings` dataset via XQL. This is the model the Cortex console renders.

The whole dataset arrives in ONE query. Requesting more than 1,000 rows makes
Cortex return a stream_id rather than the rows, and get_query_results_stream then
delivers the complete result set. An earlier version worked around the 1,000-row
inline cap by partitioning the query per asset and paging each one, which cost
455 queries and 32 minutes for 290k findings where the stream costs one query and
about 80 seconds. Queries are charged against a quota, so this matters for money
as well as time.

IMPORTANT, learned the hard way: the legacy Cortex XDR datasets `va_cves` and
`va_endpoints` still exist on new-platform tenants and still return internally
consistent, freshly-calculated data, but they do NOT match what the console shows
and they omit most of the estate. An import built on them understated the real
position by roughly 70% and attributed findings to hosts the console reports as
clean. Use `findings` with category = VULNERABILITY and is_active = true; it
reconciles to the console's own CSV export.

Usage:
    python3 cortex_import.py --env-file .env.cortex.mcr --customer MCR
    python3 cortex_import.py --env-file .env.cortex.mcr --customer MCR --dry-run

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

# get_query_results returns at most this many rows inline and reports the cap as
# the total rather than signalling truncation.
PAGE_SIZE = 1000

# Asking for more than PAGE_SIZE switches Cortex to the streaming route: the
# reply carries a stream_id instead of data, and the whole result set is then
# fetched in one go. This is the documented mechanism for large results.
STREAM_LIMIT = 500000

VULN_FILTER = ('xdm.finding.category = "VULNERABILITY" '
               'and xdm.finding.is_active = true')

NF = "xdm.finding.normalized_fields"


def _load_env(path: Path, override: bool = False) -> bool:
    if not path.exists():
        return False
    for line in path.read_text().splitlines():
        line = line.strip()
        if "=" not in line or line.startswith("#"):
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        if override:
            os.environ[k] = v
        else:
            os.environ.setdefault(k, v)
    return True


_load_env(Path(__file__).parent / ".env.cortex")

BASE_URL   = os.environ.get("CORTEX_BASE_URL", "")
API_KEY_ID = os.environ.get("CORTEX_API_KEY_ID", "")
API_KEY    = os.environ.get("CORTEX_API_KEY", "")

sys.path.insert(0, str(Path(__file__).parent))
from app import app, db, cvss_to_severity, resolve_severity, SEV_LEVEL, apply_suppression_rules
from models import ScanImport, Vulnerability


# Cortex caps how many XQL queries may run at once (four, per the API docs) and
# rejects the excess with a 500. That is back-pressure, not a failure, so wait and
# retry. The import now issues a handful of queries rather than hundreds, so this
# should be rare, but another job on the same tenant can still trigger it.
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
            transient = e.code in (429, 500, 502, 503) and (_BUSY in detail or e.code in (429, 502, 503))
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
    """Start a query and wait for it. Returns the reply once it has finished."""
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
    """A single page of results, for small queries such as counts."""
    rep = _run_query(query, days, limit)
    return (rep.get("results") or {}).get("data") or []


def xql_stream(query, days=1, progress=None):
    """
    Every row of a result set, however large, in one query.

    Asking for more than PAGE_SIZE rows makes Cortex return a stream_id in place
    of the data, which get_query_results_stream then delivers in full. That is
    the documented route for large results and it costs one query, where paging
    the same data an asset at a time cost several hundred.
    """
    rep = _run_query(query, days, STREAM_LIMIT)
    results = rep.get("results") or {}

    # Small result sets still come back inline, so there is nothing to stream.
    if results.get("data") is not None and not results.get("stream_id"):
        return results["data"] or []

    stream_id = results.get("stream_id")
    if not stream_id:
        return []
    expected = rep.get("number_of_results") or 0
    if progress:
        progress(f"  streaming {expected:,} rows in one query "
                 f"(cost {_cost_of(rep):.4f})")

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

    # The payload is gzipped by the stream itself and again by the transport,
    # so peel until it stops being gzip rather than assuming a fixed depth.
    while raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    if progress:
        progress(f"  received {len(raw) / 1048576:.0f} MB")

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


def _cost_of(rep):
    vals = list((rep.get("query_cost_charged") or {}).values())
    return vals[0] if vals else 0.0


def expected_total(days):
    rows = xql(f"dataset = findings | filter {VULN_FILTER} | comp count() as n", days)
    return (rows[0].get("n") if rows else 0) or 0


def fetch_asset_ips(days):
    """Asset name -> IP string, from asset_inventory. Best effort."""
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


def ms_to_dt(ms):
    if not ms:
        return None
    try:
        return datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc).replace(tzinfo=None)
    except Exception:
        return None


def iso_to_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None


def prior_first_seen(customer_id):
    """Earliest first_seen already recorded per (asset, CVE) for this customer."""
    rows = (db.session.query(Vulnerability.asset,
                             Vulnerability.vulnerability_id,
                             db.func.min(Vulnerability.first_seen))
            .join(ScanImport, Vulnerability.scan_import_id == ScanImport.id)
            .filter(ScanImport.customer_id == customer_id,
                    Vulnerability.source == "cortex",
                    Vulnerability.first_seen.isnot(None))
            .group_by(Vulnerability.asset, Vulnerability.vulnerability_id)
            .all())
    return {(a, v): fs for a, v, fs in rows}


def build_record(r, ips, carried, now):
    nf = r.get(NF) or {}
    cve = nf.get("xdm.vulnerability.cve_id") or ""
    if not cve:
        return None
    asset = (r.get("xdm.finding.asset_name") or "").strip()
    if not asset:
        return None

    try:
        score = float(nf.get("xdm.vulnerability.cvss_score"))
    except (TypeError, ValueError):
        score = None
    sev_text = (nf.get("xdm.vulnerability.severity") or "").strip().title() or None
    risk = resolve_severity(None, sev_text, score, None)

    pkg   = nf.get("xdm.software_package.id") or ""
    pkver = nf.get("xdm.software_package.version") or ""
    software = f"{pkg} {pkver}".strip() or None

    fixes = nf.get("xdm.vulnerability.fix_versions") or []
    if isinstance(fixes, str):
        fixes = [fixes]
    patches = ", ".join(str(f) for f in fixes)[:500] or None

    first_obs = ms_to_dt(r.get("xdm.finding.first_observed"))
    last_obs  = ms_to_dt(r.get("xdm.finding.last_observed"))
    published = iso_to_dt(nf.get("xdm.vulnerability.publish_date"))
    # first_observed is often null; fall back to the CVE publish date, then last seen.
    seed = first_obs or published or last_obs or now
    first_seen = carried.get((asset, cve), seed)

    os_bits = " ".join(str(x) for x in (nf.get("xdm.host.os_distribution"),
                                        nf.get("xdm.host.os_release")) if x)
    exploitable = nf.get("xdm.vulnerability.exploitable")
    epss = nf.get("xdm.vulnerability.epss_score")
    labels = []
    if exploitable:
        labels.append("exploitable")
    if nf.get("xdm.vulnerability.has_a_fix"):
        labels.append("has-fix")
    if isinstance(epss, (int, float)) and epss:
        labels.append(f"epss={epss}")

    return dict(
        vulnerability_id = cve,
        suppressed       = False,
        asset            = asset,
        ip_address       = ips.get(asset, "") or "",
        source           = "cortex",
        labels           = ", ".join(labels)[:500],
        first_seen       = first_seen,
        last_seen        = last_obs or now,
        cvss_v3_severity = sev_text,
        cvss_v3_score    = score,
        cvss_v4_severity = None,
        cvss_v4_score    = None,
        available_patches= patches,
        affected_software= software,
        plugin_id        = cve,
        plugin_name      = cve,
        plugin_family    = r.get("xdm.finding.asset_type") or "",
        risk_factor      = risk,
        severity_level   = SEV_LEVEL.get(risk, 0),
        synopsis         = (r.get("xdm.finding.name") or "")[:500],
        description      = (r.get("xdm.finding.description_template")
                            or r.get("xdm.finding.description") or ""),
        solution         = (f"Upgrade {pkg} to {patches}" if pkg and patches else ""),
        port             = "",
        protocol         = "",
        plugin_output    = os_bits,
        cpe              = (nf.get("xdm.software_package.purl") or "")[:500],
    )


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--days", type=int, default=int(os.environ.get("CORTEX_DAYS", "1")),
                   help="XQL lookback window in days (findings is current-state; default 1)")
    p.add_argument("--notes", default="")
    p.add_argument("--customer", default=os.environ.get("PORTAL_CUSTOMER", ""))
    p.add_argument("--env-file", default="")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    global BASE_URL, API_KEY_ID, API_KEY
    if args.env_file:
        ef = Path(args.env_file)
        if not ef.is_absolute():
            ef = Path(__file__).parent / ef
        if not _load_env(ef, override=True):
            raise SystemExit(f"ERROR: credentials file not found: {ef}")
        BASE_URL   = os.environ.get("CORTEX_BASE_URL", BASE_URL)
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
    print(f"Source: findings dataset, category VULNERABILITY, active only", flush=True)

    expected = expected_total(args.days)
    print(f"Cortex reports {expected:,} active vulnerability findings", flush=True)
    if carried:
        print(f"  carrying first_seen forward for {len(carried):,} known findings", flush=True)

    print("Fetching asset IP inventory...", flush=True)
    ips = fetch_asset_ips(args.days)
    print(f"  {len(ips)} assets with IP data", flush=True)

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    FIELDS = ("xdm.finding.id, xdm.finding.asset_name, xdm.finding.asset_type, "
              "xdm.finding.name, xdm.finding.description_template, "
              "xdm.finding.first_observed, xdm.finding.last_observed, "
              f"{NF}")

    print("Fetching all findings in a single streamed query...", flush=True)
    rows = xql_stream(f"dataset = findings | filter {VULN_FILTER} | fields {FIELDS}",
                      args.days, progress=lambda m: print(m, flush=True))

    records, seen_ids = [], set()
    for r in rows:
        fid = r.get("xdm.finding.id")
        if fid in seen_ids:
            continue
        seen_ids.add(fid)
        rec = build_record(r, ips, carried, now)
        if rec:
            records.append(rec)

    print(f"\nRetrieved {len(records):,} findings (Cortex reported {expected:,})")
    delta = len(records) - expected
    if abs(delta) > max(50, expected * 0.01):
        print(f"  WARNING: differs from the Cortex total by {delta:+,}")
    else:
        print(f"  reconciles to within {delta:+,}")

    if not records:
        print("Nothing to import.")
        return

    sev = Counter(r["risk_factor"] for r in records)
    print("\nSeverity breakdown:")
    for s, n in sorted(sev.items(), key=lambda x: -SEV_LEVEL.get(x[0], 0)):
        print(f"  {s:14} {n:>8,}")

    hosts = Counter(r["asset"] for r in records)
    print(f"\nAffected assets: {len(hosts)}")
    print("Top 10:")
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
        scan_name = f"Cortex-{now.strftime('%Y-%m-%d')}.api"
        scan = ScanImport(filename=scan_name, report_date=now.date(),
                          customer_id=customer.id, imported_by_id=None,
                          notes=args.notes or "Automated Cortex import (findings dataset)")
        db.session.add(scan)
        db.session.flush()
        CHUNK = 5000
        for i in range(0, len(records), CHUNK):
            db.session.bulk_save_objects([
                Vulnerability(scan_import_id=scan.id, **r) for r in records[i:i + CHUNK]])
            db.session.flush()
        scan.record_count = len(records)
        db.session.commit()

        # Re-apply this customer's false-positive determinations. Suppression is
        # stored as a rule; the row flag is its cached effect, so without this
        # every determination would lapse at each import.
        n = apply_suppression_rules(customer.id, scan.id)
        if n:
            print(f"  Re-applied suppression rules to {n:,} finding(s)", flush=True)
    print(f"Done, imported {len(records):,} findings as '{scan_name}'")


if __name__ == "__main__":
    main()
