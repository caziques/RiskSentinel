#!/usr/bin/env python3
"""
LevelBlue / AlienVault USM → vuln-portal direct importer.

Fetches vulnerabilities from the LevelBlue API (filtered to the chosen sources,
valid=true, suppressed=No, last 7 days) and imports them directly into the
vuln-portal SQLite database — no CSV upload required.

Usage:
    python3 levelblue_import.py [--days 7] [--notes "Weekly automated import"]

Cron example (every Monday 06:00):
    0 6 * * MON cd /Users/mynhardt/claude/vuln-portal && .venv/bin/python levelblue_import.py
"""

import argparse
import base64
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import requests

# ── Credentials ───────────────────────────────────────────────────────────────
# Each USM tenant has its own credentials, so --env-file selects which set to use.
# Without it the default .env.levelblue applies, preserving existing behaviour.

def _load_env(path: Path, override: bool = False) -> bool:
    """Read KEY=VALUE lines into the environment. Returns False if absent."""
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


_load_env(Path(__file__).parent / ".env.levelblue")

BASE_URL      = os.environ.get("LEVELBLUE_BASE_URL", "https://nebula-group.alienvault.cloud")
CLIENT_ID     = os.environ.get("LEVELBLUE_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("LEVELBLUE_CLIENT_SECRET", "")
PAGE_SIZE     = 500

# "<family> <plugin name> <numeric plugin id>"
_OVAL_RE = re.compile(r"^(.*?)\s+(\d+)$")

# ── Flask app context ─────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from app import app, db, cvss_to_severity, resolve_severity, SEV_LEVEL, apply_suppression_rules
from models import ScanImport, Vulnerability


# ── LevelBlue API helpers ─────────────────────────────────────────────────────

def get_token() -> str:
    creds = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    r = requests.post(
        f"{BASE_URL}/api/2.0/oauth/token",
        headers={"Authorization": f"Basic {creds}",
                 "Content-Type": "application/x-www-form-urlencoded"},
        data="grant_type=client_credentials",
        timeout=30,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def paginate(session: requests.Session, path: str, key: str):
    page = 0
    total_pages = None
    while True:
        r = session.get(f"{BASE_URL}{path}?page={page}&size={PAGE_SIZE}", timeout=60)
        r.raise_for_status()
        data = r.json()
        yield from data.get("_embedded", {}).get(key, [])
        if total_pages is None:
            total_pages = data.get("page", {}).get("totalPages", 1)
            total_el    = data.get("page", {}).get("totalElements", "?")
            print(f"  {path}: {total_el} records, {total_pages} pages", flush=True)
        page += 1
        if page >= total_pages:
            break


def ms_to_dt(ms) -> datetime | None:
    if not ms:
        return None
    try:
        return datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc).replace(tzinfo=None)
    except Exception:
        return None


def patches_text(patches: list) -> str:
    if not patches:
        return ""
    return "; ".join(p.get("name", "") for p in patches if p.get("name"))


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=7,
                        help="Import findings seen in the last N days (default 7)")
    parser.add_argument("--notes", default="",
                        help="Notes to attach to the ScanImport record")
    parser.add_argument("--customer", default="",
                        help="Customer name to import into (defaults to 'Default')")
    parser.add_argument("--sources", default="tenabletvsapp",
                        help="Comma-separated USM sources to import. Tenants differ: "
                             "Tenable-based ones use tenabletvsapp, SentinelOne-based "
                             "ones need sentinelone (default: tenabletvsapp)")
    parser.add_argument("--env-file", default="",
                        help="Credentials file for this tenant, relative to the script "
                             "directory or an absolute path (default: .env.levelblue)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Fetch and summarise without writing to the database")
    args = parser.parse_args()

    # Per-tenant credentials override the defaults loaded at import time.
    if args.env_file:
        global BASE_URL, CLIENT_ID, CLIENT_SECRET
        ef = Path(args.env_file)
        if not ef.is_absolute():
            ef = Path(__file__).parent / ef
        if not _load_env(ef, override=True):
            raise SystemExit(f"ERROR: credentials file not found: {ef}")
        BASE_URL      = os.environ.get("LEVELBLUE_BASE_URL", BASE_URL)
        CLIENT_ID     = os.environ.get("LEVELBLUE_CLIENT_ID", "")
        CLIENT_SECRET = os.environ.get("LEVELBLUE_CLIENT_SECRET", "")

    if not CLIENT_ID or not CLIENT_SECRET:
        raise SystemExit("ERROR: LEVELBLUE_CLIENT_ID / LEVELBLUE_CLIENT_SECRET not set.")

    sources = {s.strip() for s in args.sources.split(",") if s.strip()}

    cutoff_ms = (time.time() - args.days * 24 * 3600) * 1000

    print(f"Tenant:  {BASE_URL}", flush=True)
    print(f"Sources: {', '.join(sorted(sources))}", flush=True)
    print("Authenticating with LevelBlue...", flush=True)
    token = get_token()
    http = requests.Session()
    http.headers.update({"Authorization": f"Bearer {token}"})

    # 1. Vulnerability definitions: id → {cve, score_v3, sev_v3, score_v4, sev_v4, patches}
    print("Fetching vulnerability definitions...", flush=True)
    vuln_defs: dict[str, dict] = {}
    for v in paginate(http, "/api/2.0/vulnerabilities", "vulnerabilities"):
        vuln_defs[v["id"]] = {
            "cve":      v.get("cve") or "",
            "score_v3": v.get("cvssScoreV3") or v.get("cvssScore"),
            "sev_v3":   v.get("cvssSeverityV3") or v.get("cvssSeverity") or "",
            "score_v4": v.get("cvssScoreV4"),
            "sev_v4":   v.get("cvssSeverityV4") or "",
            "patches":  patches_text(v.get("patches") or []),
        }
    print(f"  {len(vuln_defs)} definitions loaded", flush=True)

    # 2. Asset index: id → {name, ip, os}
    print("Fetching asset index...", flush=True)
    assets: dict[str, dict] = {}
    for a in paginate(http, "/api/2.0/assets", "assets"):
        ips = []
        for iface in a.get("networkInterfaces") or []:
            ips.extend(iface.get("ipv4") or [])
        assets[a["id"]] = {
            "name": a.get("name") or a.get("id"),
            "ip":   ", ".join(ips) if ips else (a.get("ip") or ""),
            "os":   a.get("operatingSystem") or "",
        }
    print(f"  {len(assets)} assets loaded", flush=True)

    # 3. Vulnerability statuses — apply all filters client-side
    print(f"Fetching vulnerability statuses (last {args.days}d, "
          f"{'/'.join(sorted(sources))}, valid, not suppressed)...", flush=True)
    records = []
    skipped = {"source": 0, "valid": 0, "suppressed": 0, "timestamp": 0}

    for vs in paginate(http, "/api/2.0/vulnerabilityStatuses", "vulnerabilityStatuses"):
        if vs.get("source") not in sources:
            skipped["source"] += 1
            continue
        if not vs.get("valid"):
            skipped["valid"] += 1
            continue
        if vs.get("suppressed") != "No":
            skipped["suppressed"] += 1
            continue
        if (vs.get("lastTimestamp") or 0) < cutoff_ms:
            skipped["timestamp"] += 1
            continue

        vid  = vs.get("vulnerabilityId") or ""
        defn = vuln_defs.get(vid, {})
        aid  = vs.get("assetId") or ""
        asset = assets.get(aid, {"name": aid, "ip": "", "os": ""})

        score_v3 = defn.get("score_v3")
        sev_v3   = defn.get("sev_v3") or ""
        score_v4 = defn.get("score_v4")
        sev_v4   = defn.get("sev_v4") or ""

        risk_factor    = resolve_severity(None, sev_v3 or None, score_v3, score_v4)
        severity_level = SEV_LEVEL.get(risk_factor, 0)

        last_seen_list = vs.get("lastSeen") or []
        last_seen_ms   = max(last_seen_list) if last_seen_list else vs.get("lastTimestamp")

        # USM packs three things into ovalRuleId: "<family> <plugin name> <id>".
        # Example: "Windows Windows Explorer Recently Executed Programs 92423".
        # Previously the whole string went into plugin_id and family was left
        # blank, which made the plugin grouping unreliable and the families chart
        # empty. Split it: the trailing number is the Tenable plugin id, and the
        # head with the plugin name removed is the family.
        oval = vs.get("ovalRuleId") or ""
        vname = vs.get("name") or ""
        plugin_id = ""
        plugin_family = ""
        m = _OVAL_RE.match(oval)
        if m:
            head, plugin_id = m.group(1), m.group(2)
            if vname and head.endswith(vname):
                plugin_family = head[:-len(vname)].strip()
            elif head:
                # no usable name to strip; keep the leading token as the family
                plugin_family = head.split(" ")[0]
        elif "def:" in oval:
            plugin_id = oval.split("def:")[-1]
        elif oval:
            plugin_id = oval[:64]
        if not plugin_family:
            # USM returns some records with no plugin metadata at all. Label them
            # rather than leaving a blank bucket on the families chart.
            plugin_family = "Uncategorised"

        records.append(dict(
            vulnerability_id = vs.get("id") or "",
            suppressed       = False,
            asset            = asset["name"],
            ip_address       = asset["ip"],
            source           = vs.get("source") or "",
            labels           = "",
            first_seen       = ms_to_dt(vs.get("firstSeen")),
            last_seen        = ms_to_dt(last_seen_ms),
            cvss_v3_severity = sev_v3 or None,
            cvss_v3_score    = score_v3,
            cvss_v4_severity = sev_v4 or None,
            cvss_v4_score    = score_v4,
            available_patches= defn.get("patches") or None,
            affected_software= vs.get("affectedSoftware") or None,
            plugin_id        = plugin_id,
            plugin_name      = vs.get("name") or defn.get("cve") or "",
            plugin_family    = plugin_family,
            risk_factor      = risk_factor,
            severity_level   = severity_level,
            synopsis         = "",
            description      = vs.get("description") or "",
            solution         = "",
            port             = "",
            protocol         = "",
            plugin_output    = "",
            cpe              = "",
        ))

    print(f"\nFilter summary:")
    print(f"  Kept      {len(records):>6}")
    for reason, count in skipped.items():
        print(f"  Skipped ({reason}) {count:>6}")

    if not records:
        print("Nothing to import.")
        return

    # 4. Write to database inside Flask app context
    fam_counts = Counter(r["plugin_family"] or "(blank)" for r in records)
    print("\nPlugin families:")
    for f, n in fam_counts.most_common(12):
        print(f"  {f:34} {n:>6,}")

    if args.dry_run:
        print("\n--dry-run: nothing written to the database.")
        return

    print("\nWriting to database...", flush=True)
    with app.app_context():
        from models import Customer
        cust_name = args.customer.strip() or "Default"
        customer  = Customer.query.filter_by(name=cust_name).first()
        if not customer:
            raise SystemExit(f"ERROR: Customer '{cust_name}' not found in database.")
        print(f"  Importing into customer: {customer.name}", flush=True)

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        scan_name = f"LevelBlue-{now.strftime('%Y-%m-%d')}.api"
        scan = ScanImport(
            filename       = scan_name,
            report_date    = now.date(),
            customer_id    = customer.id,
            imported_by_id = None,  # automated — no user session
            notes          = args.notes or f"Automated LevelBlue import — last {args.days} days",
        )
        db.session.add(scan)
        db.session.flush()  # get scan.id

        db.session.bulk_save_objects([
            Vulnerability(scan_import_id=scan.id, **r) for r in records
        ])
        scan.record_count = len(records)
        db.session.commit()

        # Re-apply this customer's false-positive determinations. Suppression is
        # stored as a rule; the row flag is its cached effect, so without this
        # every determination would lapse at each import.
        n = apply_suppression_rules(customer.id, scan.id)
        if n:
            print(f"  Re-applied suppression rules to {n:,} finding(s)", flush=True)

    print(f"Done — imported {len(records):,} vulnerabilities as '{scan_name}'")

    # Summary
    sev_counts = Counter(r["risk_factor"] for r in records)
    print("\nSeverity breakdown:")
    for sev, cnt in sorted(sev_counts.items(), key=lambda x: -SEV_LEVEL.get(x[0], 0)):
        print(f"  {sev:14} {cnt:>5}")

    asset_counts = Counter(r["asset"] for r in records)
    print("\nTop 10 assets:")
    for asset, cnt in asset_counts.most_common(10):
        print(f"  {cnt:>4}  {asset}")


if __name__ == "__main__":
    main()
