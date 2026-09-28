#!/usr/bin/env python3
"""
LevelBlue / AlienVault USM vulnerability fetcher.
Authenticates via OAuth, pages through all vulnerability definitions and
statuses, joins them, and writes a CSV of High/Critical findings.

Usage:
    python3 levelblue_fetch.py [--min-score 7.0] [--output report.csv]
"""

import argparse
import base64
import csv
import os
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import requests

# Load .env.levelblue from same directory if present
_env_file = Path(__file__).parent / ".env.levelblue"
if _env_file.exists():
    for _line in _env_file.read_text().splitlines():
        if "=" in _line and not _line.startswith("#"):
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip())

BASE_URL      = os.environ.get("LEVELBLUE_BASE_URL", "https://nebula-group.alienvault.cloud")
CLIENT_ID     = os.environ.get("LEVELBLUE_CLIENT_ID", "littlebot")
CLIENT_SECRET = os.environ.get("LEVELBLUE_CLIENT_SECRET", "")
PAGE_SIZE     = 500


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
    """Yield all items from a paginated HAL endpoint."""
    page = 0
    total_pages = None
    while True:
        url = f"{BASE_URL}{path}?page={page}&size={PAGE_SIZE}"
        r = session.get(url, timeout=60)
        r.raise_for_status()
        data = r.json()
        items = data.get("_embedded", {}).get(key, [])
        yield from items
        if total_pages is None:
            total_pages = data.get("page", {}).get("totalPages", 1)
            total_el = data.get("page", {}).get("totalElements", "?")
            print(f"  {path}: {total_el} total records, {total_pages} pages", flush=True)
        page += 1
        if page >= total_pages:
            break


def ts_to_iso(ms) -> str:
    if not ms:
        return ""
    try:
        return datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return str(ms)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="levelblue_vulns.csv",
                        help="Output CSV filename")
    args = parser.parse_args()

    print("Authenticating...", flush=True)
    token = get_token()
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {token}"})

    # 1. Build vulnerability definition cache: id -> {cve, score, severity, referenceUrl}
    print("Loading vulnerability definitions...", flush=True)
    vuln_defs: dict[str, dict] = {}
    for v in paginate(session, "/api/2.0/vulnerabilities", "vulnerabilities"):
        vuln_defs[v["id"]] = {
            "cve":          v.get("cve") or "",
            "score":        v.get("cvssScoreV3") or v.get("cvssScore"),
            "severity":     v.get("cvssSeverityV3") or v.get("cvssSeverity") or "",
            "score_v4":     v.get("cvssScoreV4"),
            "severity_v4":  v.get("cvssSeverityV4") or "",
            "ref_url":      v.get("referenceUrl") or "",
        }
    print(f"  Loaded {len(vuln_defs)} definitions", flush=True)

    # 2. Stream vulnerability statuses and join with definitions
    print("Loading vulnerability statuses...", flush=True)
    rows = []

    # Also need asset names — load lazily from status assetId, or pre-fetch
    # Pre-fetch asset name+IP map
    print("Loading asset index...", flush=True)
    assets: dict[str, dict] = {}
    for a in paginate(session, "/api/2.0/assets", "assets"):
        ips = []
        for iface in a.get("networkInterfaces", []) or []:
            for ip in iface.get("ipv4", []) or []:
                ips.append(ip)
        assets[a["id"]] = {
            "name": a.get("name") or a.get("id"),
            "ip":   ", ".join(ips) if ips else a.get("ip") or "",
            "os":   a.get("operatingSystem") or "",
        }
    print(f"  Loaded {len(assets)} assets", flush=True)

    cutoff_ms = (time.time() - 7 * 24 * 3600) * 1000  # now-7d in milliseconds

    print("Processing vulnerability statuses...", flush=True)
    skipped_source = 0
    skipped_valid = 0
    skipped_suppressed = 0
    skipped_timestamp = 0
    for vs in paginate(session, "/api/2.0/vulnerabilityStatuses", "vulnerabilityStatuses"):
        if vs.get("source") != "tenabletvsapp":
            skipped_source += 1
            continue
        if not vs.get("valid"):
            skipped_valid += 1
            continue
        if vs.get("suppressed") != "No":
            skipped_suppressed += 1
            continue
        if (vs.get("lastTimestamp") or 0) < cutoff_ms:
            skipped_timestamp += 1
            continue

        vid  = vs.get("vulnerabilityId") or ""
        defn = vuln_defs.get(vid, {})
        score = defn.get("score")

        if score is None:
            score = ""

        aid   = vs.get("assetId") or ""
        asset = assets.get(aid, {"name": aid, "ip": "", "os": ""})
        last_seen_list = vs.get("lastSeen") or []
        last_seen = ts_to_iso(max(last_seen_list)) if last_seen_list else ""

        rows.append({
            "Asset":       asset["name"],
            "IP":          asset["ip"],
            "OS":          asset["os"],
            "CVE":         defn.get("cve") or vs.get("cve") or vs.get("name") or "",
            "Score_V3":    score,
            "Severity":    defn.get("severity") or "",
            "Score_V4":    defn.get("score_v4") or "",
            "Severity_V4": defn.get("severity_v4") or "",
            "Description": (vs.get("description") or "")[:200],
            "First_Seen":  ts_to_iso(vs.get("firstSeen")),
            "Last_Seen":   last_seen,
            "Suppressed":  vs.get("suppressed") or "",
            "Ref_URL":     defn.get("ref_url") or "",
        })

    print(f"  Kept {len(rows)} findings")
    print(f"  Skipped {skipped_source} (not tenabletvsapp)")
    print(f"  Skipped {skipped_valid} (valid=false)")
    print(f"  Skipped {skipped_suppressed} (suppressed)")
    print(f"  Skipped {skipped_timestamp} (older than 7 days)")

    if not rows:
        print("No findings to write.")
        return

    rows.sort(key=lambda r: (-(r["Score_V3"] or 0), r["Asset"] or ""))

    fieldnames = ["Asset", "IP", "OS", "CVE", "Score_V3", "Severity",
                  "Score_V4", "Severity_V4", "Description",
                  "First_Seen", "Last_Seen", "Suppressed", "Ref_URL"]

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nWrote {len(rows)} rows to {args.output}")

    # Print severity summary
    sev_counts = Counter(r["Severity"] for r in rows)
    print("\nSeverity breakdown:")
    for sev, count in sorted(sev_counts.items(), key=lambda x: -x[1]):
        print(f"  {sev:10} {count:>5}")

    # Top 10 assets by finding count
    asset_counts = Counter(r["Asset"] for r in rows)
    print("\nTop 10 assets by High/Critical finding count:")
    for asset, count in asset_counts.most_common(10):
        print(f"  {count:>4}  {asset}")


if __name__ == "__main__":
    main()
