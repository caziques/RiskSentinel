#!/usr/bin/env python3
"""
Rapid7 InsightVM Cloud vulnerability fetcher.

Uses the Rapid7 Bulk Export GraphQL API to download a full vulnerability
findings snapshot (all current findings) and writes a CSV report.

Usage:
    python3 rapid7_fetch.py [--output rapid7_vulns.csv] [--min-score 0]

Env file (.env.rapid7 in same directory):
    RAPID7_API_KEY=your_api_key_here
    RAPID7_REGION=eu          # us, us2, us3, eu, ca, au, ap
"""

import argparse
import csv
import io
import os
import time
from collections import Counter
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="rapid7_vulns.csv", help="Output CSV filename")
    parser.add_argument("--min-score", type=float, default=0.0,
                        help="Minimum CVSS v3 score to include (0 = all)")
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

    # Apply min score filter
    if args.min_score > 0:
        before = len(findings_df)
        findings_df = findings_df[
            findings_df["cvssV3Score"].fillna(findings_df["cvssScore"].fillna(0)) >= args.min_score
        ]
        print(f"  {before - len(findings_df):,} filtered (below score {args.min_score})", flush=True)

    # Join with asset data
    findings_df = findings_df.join(assets_df, on="assetId", how="left")

    rows = []
    def str_or(val, fallback=""):
        return str(val) if (val is not None and not (isinstance(val, float) and pd.isna(val))) else fallback

    for _, row in findings_df.iterrows():
        score_v3 = float(row["cvssV3Score"]) if pd.notna(row.get("cvssV3Score")) else None
        sev_v3   = str_or(row.get("cvssV3Severity"))
        score_v2 = float(row["cvssScore"])   if pd.notna(row.get("cvssScore")) else None
        severity = SEV_MAP.get((str_or(row.get("severity"))).lower(), str_or(row.get("severity")))

        rows.append({
            "Asset":        str_or(row.get("hostName")) or str_or(row.get("ip")) or str_or(row.get("assetId")),
            "IP":           str_or(row.get("ip")),
            "OS":           str_or(row.get("osDescription")),
            "Vuln_ID":      str_or(row.get("vulnId")),
            "CVE":          cves_str(row.get("cves")),
            "Title":        str_or(row.get("title")),
            "Score_V3":     score_v3 if score_v3 is not None else "",
            "Severity_V3":  sev_v3,
            "Score_V2":     score_v2 if score_v2 is not None else "",
            "Severity":     severity,
            "Has_Exploits": "Yes" if row.get("hasExploits") else "",
            "EPSS":         str_or(row.get("epssscore")),
            "Port":         int(row["port"]) if pd.notna(row.get("port")) else "",
            "Protocol":     str_or(row.get("protocol")),
            "First_Found":  str(row["firstFoundTimestamp"])[:10] if pd.notna(row.get("firstFoundTimestamp")) else "",
            "Description":  str_or(row.get("description"))[:200],
        })

    rows.sort(key=lambda r: (-(float(r["Score_V3"]) if r["Score_V3"] else 0), str(r["Asset"])))

    fieldnames = [
        "Asset", "IP", "OS", "Vuln_ID", "CVE", "Title",
        "Score_V3", "Severity_V3", "Score_V2", "Severity",
        "Has_Exploits", "EPSS", "Port", "Protocol", "First_Found", "Description",
    ]

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nWrote {len(rows):,} findings to {args.output}")

    sev_counts = Counter(r["Severity"] for r in rows)
    print("\nSeverity breakdown:")
    order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    for sev, count in sorted(sev_counts.items(), key=lambda x: -order.get(x[0], 0)):
        print(f"  {sev:10} {count:>5}")

    asset_counts = Counter(r["Asset"] for r in rows)
    print("\nTop 10 assets by finding count:")
    for asset, count in asset_counts.most_common(10):
        print(f"  {count:>4}  {asset}")


if __name__ == "__main__":
    main()
