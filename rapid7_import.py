#!/usr/bin/env python3
"""
Rapid7 InsightVM Cloud → vuln-portal direct importer.

Uses the Rapid7 Bulk Export GraphQL API to download a full vulnerability
findings snapshot and imports it directly into the vuln-portal SQLite database.

Usage:
    python3 rapid7_import.py [--min-score 0] [--notes "Weekly import"]

Env file (.env.rapid7 in same directory):
    RAPID7_API_KEY=your_api_key_here
    RAPID7_REGION=eu          # us, us2, us3, eu, ca, au, ap

Cron example (every Monday 06:00):
    0 6 * * MON cd /Users/mynhardt/claude/vuln-portal && .venv/bin/python rapid7_import.py
"""

import argparse
import io
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import requests

_env_file = Path(__file__).parent / ".env.rapid7"
if _env_file.exists():
    for _line in _env_file.read_text().splitlines():
        if "=" in _line and not _line.startswith("#"):
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip())

REGION   = os.environ.get("RAPID7_REGION", "us")
API_KEY  = os.environ.get("RAPID7_API_KEY", "")
BASE_URL = f"https://{REGION}.api.insight.rapid7.com"

sys.path.insert(0, str(Path(__file__).parent))
from app import app, db, resolve_severity, SEV_LEVEL
from models import ScanImport, Vulnerability

# Rapid7 severity → portal risk_factor
SEV_MAP = {
    "critical": "Critical",
    "severe":   "High",
    "moderate": "Medium",
    "low":      "Low",
}


def gql(query: str) -> dict:
    r = requests.post(
        f"{BASE_URL}/export/graphql",
        headers={"X-Api-Key": API_KEY, "Content-Type": "application/json"},
        json={"query": query},
        timeout=30,
    )
    r.raise_for_status()
    data = r.json()
    if "errors" in data:
        raise RuntimeError(f"GraphQL error: {data['errors']}")
    return data["data"]


def trigger_export() -> str:
    result = gql("""
    mutation {
      createVulnerabilityExport(input: { source: IVM, format: PARQUET }) {
        id status
      }
    }
    """)
    export_id = result["createVulnerabilityExport"]["id"]
    print(f"  Export ID: {export_id}", flush=True)
    return export_id


def wait_for_export(export_id: str, poll_interval: int = 10, timeout: int = 600) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(poll_interval)
        data = gql(f"""{{ export(id: "{export_id}") {{ status result {{ prefix urls }} }} }}""")
        status = data["export"]["status"]
        print(f"  Status: {status}", flush=True)
        if status == "SUCCEEDED":
            return {g["prefix"]: g["urls"] for g in data["export"]["result"]}
        if status == "FAILED":
            raise RuntimeError("Export job failed")
    raise TimeoutError(f"Export did not complete within {timeout}s")


def download_parquet(url: str) -> pd.DataFrame:
    r = requests.get(url, timeout=120)
    r.raise_for_status()
    return pd.read_parquet(io.BytesIO(r.content))


def cves_str(val) -> str:
    if val is None:
        return ""
    if isinstance(val, list):
        return ", ".join(str(v) for v in val if v)
    return str(val)


def to_dt(val) -> datetime | None:
    if val is None or (hasattr(val, '__class__') and val.__class__.__name__ == 'NaTType'):
        return None
    try:
        import pandas as pd
        if pd.isna(val):
            return None
    except Exception:
        pass
    if hasattr(val, 'to_pydatetime'):
        return val.to_pydatetime().replace(tzinfo=None)
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--min-score", type=float, default=0.0,
                        help="Minimum CVSS v3 score to import (0 = all)")
    parser.add_argument("--notes", default="",
                        help="Notes to attach to the ScanImport record")
    parser.add_argument("--customer", default="",
                        help="Customer name to import into (defaults to 'Default')")
    args = parser.parse_args()

    if not API_KEY:
        raise SystemExit("ERROR: RAPID7_API_KEY not set. Create .env.rapid7 or export the variable.")

    print("Triggering vulnerability export...", flush=True)
    export_id = trigger_export()

    print("Waiting for export to complete...", flush=True)
    url_groups = wait_for_export(export_id)

    print("Downloading asset data...", flush=True)
    assets_df = download_parquet(url_groups["asset"][0])
    assets_df = assets_df[["assetId", "hostName", "ip", "osDescription"]].copy()
    assets_df = assets_df.set_index("assetId")

    print("Downloading vulnerability findings...", flush=True)
    findings_df = download_parquet(url_groups["asset_vulnerability"][0])
    print(f"  {len(findings_df):,} raw findings", flush=True)

    if args.min_score > 0:
        before = len(findings_df)
        findings_df = findings_df[
            findings_df["cvssV3Score"].fillna(findings_df["cvssScore"].fillna(0)) >= args.min_score
        ]
        print(f"  {before - len(findings_df):,} filtered (below score {args.min_score})", flush=True)

    findings_df = findings_df.join(assets_df, on="assetId", how="left")

    def str_or(v):
        return str(v) if (v is not None and not (isinstance(v, float) and pd.isna(v))) else ""

    records = []
    for _, row in findings_df.iterrows():
        score_v3 = float(row["cvssV3Score"]) if pd.notna(row.get("cvssV3Score")) else None
        sev_v3   = str_or(row.get("cvssV3Severity")) or None
        score_v2 = float(row["cvssScore"])   if pd.notna(row.get("cvssScore"))   else None

        r7_sev       = str_or(row.get("severity")).lower()
        risk_factor  = SEV_MAP.get(r7_sev) or resolve_severity(None, sev_v3, score_v3, None)
        sev_level    = SEV_LEVEL.get(risk_factor, 0)

        hostname = str_or(row.get("hostName")) or str_or(row.get("ip")) or str_or(row.get("assetId"))
        ip       = str_or(row.get("ip"))
        os_desc  = str_or(row.get("osDescription"))

        port = str(int(row["port"])) if pd.notna(row.get("port")) else ""

        records.append(dict(
            vulnerability_id  = str(row.get("vulnId") or ""),
            suppressed        = False,
            asset             = hostname,
            ip_address        = ip,
            source            = "rapid7",
            labels            = "",
            first_seen        = to_dt(row.get("firstFoundTimestamp")),
            last_seen         = to_dt(row.get("firstFoundTimestamp")),
            cvss_v3_severity  = sev_v3,
            cvss_v3_score     = score_v3,
            cvss_v4_severity  = None,
            cvss_v4_score     = None,
            available_patches = None,
            affected_software = None,
            plugin_id         = str(row.get("vulnId") or ""),
            plugin_name       = str(row.get("title") or cves_str(row.get("cves")) or ""),
            plugin_family     = "",
            risk_factor       = risk_factor,
            severity_level    = sev_level,
            synopsis          = "",
            description       = (str(row.get("description") or ""))[:2000],
            solution          = "",
            port              = port,
            protocol          = str(row.get("protocol") or ""),
            plugin_output     = (str(row.get("proof") or ""))[:1000],
            cpe               = "",
        ))

    print(f"\nPrepared {len(records):,} records for import", flush=True)

    if not records:
        print("Nothing to import.")
        return

    print("Writing to database...", flush=True)
    with app.app_context():
        from models import Customer
        cust_name = args.customer.strip() or "Default"
        customer  = Customer.query.filter_by(name=cust_name).first()
        if not customer:
            raise SystemExit(f"ERROR: Customer '{cust_name}' not found in database.")
        print(f"  Importing into customer: {customer.name}", flush=True)

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        scan_name = f"Rapid7-{now.strftime('%Y-%m-%d')}.api"
        scan = ScanImport(
            filename       = scan_name,
            report_date    = now.date(),
            customer_id    = customer.id,
            imported_by_id = None,
            notes          = args.notes or f"Automated Rapid7 InsightVM export — {now.strftime('%Y-%m-%d')}",
        )
        db.session.add(scan)
        db.session.flush()

        db.session.bulk_save_objects([
            Vulnerability(scan_import_id=scan.id, **r) for r in records
        ])
        scan.record_count = len(records)
        db.session.commit()

    print(f"Done — imported {len(records):,} vulnerabilities as '{scan_name}'")

    from collections import Counter
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
