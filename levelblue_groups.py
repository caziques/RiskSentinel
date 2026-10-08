#!/usr/bin/env python3
"""
Sync LevelBlue / USM Anywhere asset groups into RiskSentinel.

USM maintains asset groups, static and dynamic, that are more current and better
curated than anything kept by hand here. This pulls them in so the per-group
views on the Vulnerabilities and CVE pages work against real groupings, and so
dynamic groups stay current without anyone editing them.

Only **static** groups that actually have members are synced. Static groups are
curated by hand in USM and carry intent. The dynamic ones are RSQL rules that
largely restate filters RiskSentinel already applies -- "Windows Assets",
"Assets with Vulnerabilities", "Linux Assets" -- and one of them holds 1,010 of
the tenant's 1,024 assets, so importing them would bury the useful groups
without adding anything. Pass --include-dynamic to take them anyway.

Empty groups are skipped either way: USM carries unused compliance shells
(PCI DSS, HIPAA) with no members.

Asset names are taken from the group's asset `name` field, matching exactly how
levelblue_import.py names assets on the findings it writes. Using `fqdn` instead
would produce groups that silently match nothing.

Usage:
    python3 levelblue_groups.py --env-file .env.levelblue --customer Nebula
    python3 levelblue_groups.py --env-file .env.levelblue --customer Nebula --dry-run

Credentials (env or --env-file):
    LEVELBLUE_BASE_URL
    LEVELBLUE_CLIENT_ID
    LEVELBLUE_CLIENT_SECRET
"""

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
from app import app, db
from models import AssetGroup, AssetGroupMember, Customer

PAGE_SIZE = 200

# USM rejects an explicit Accept header on the 2.0 API and answers 500 to every
# endpoint, including ones that plainly work. Send Authorization only.
BASE_URL = CLIENT_ID = CLIENT_SECRET = None




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


def get_session():
    r = requests.post(f"{BASE_URL}/api/2.0/oauth/token",
                      auth=(CLIENT_ID, CLIENT_SECRET),
                      data={"grant_type": "client_credentials"}, timeout=60)
    r.raise_for_status()
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {r.json()['access_token']}"})
    return s


def paginate(session, path, key):
    page = 0
    while True:
        sep = "&" if "?" in path else "?"
        r = session.get(f"{BASE_URL}{path}{sep}page={page}&size={PAGE_SIZE}", timeout=90)
        r.raise_for_status()
        j = r.json()
        items = (j.get("_embedded") or {}).get(key) or []
        for it in items:
            yield it
        pg = j.get("page") or {}
        total = pg.get("totalPages") or 1
        page += 1
        if page >= total or not items:
            break


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--customer", required=True)
    p.add_argument("--env-file", default="")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--include-dynamic", action="store_true",
                   help="also sync USM's rule-based dynamic groups (default: static only)")
    p.add_argument("--prune", action="store_true",
                   help="delete previously synced groups that USM no longer has")
    args = p.parse_args()

    global BASE_URL, CLIENT_ID, CLIENT_SECRET
    if args.env_file:
        if not _load_env(Path(args.env_file), override=True):
            raise SystemExit(f"ERROR: --env-file not found: {args.env_file}")
    else:
        _load_env(Path(__file__).with_name(".env"))
    BASE_URL      = (os.environ.get("LEVELBLUE_BASE_URL") or "").rstrip("/")
    CLIENT_ID     = os.environ.get("LEVELBLUE_CLIENT_ID") or ""
    CLIENT_SECRET = os.environ.get("LEVELBLUE_CLIENT_SECRET") or ""
    if not (BASE_URL and CLIENT_ID and CLIENT_SECRET):
        raise SystemExit("ERROR: LEVELBLUE_BASE_URL / CLIENT_ID / CLIENT_SECRET not set.")

    with app.app_context():
        customer = Customer.query.filter_by(name=args.customer.strip()).first()
        if not customer:
            raise SystemExit(f"ERROR: Customer '{args.customer}' not found.")
        cust_id, cust_name = customer.id, customer.name

    print(f"Tenant:   {BASE_URL}")
    print(f"Customer: {cust_name}")
    print("Authenticating...", flush=True)
    http = get_session()

    groups = list(paginate(http, "/api/2.0/assetGroups", "assetGroups"))
    print(f"  {len(groups)} asset group(s) in USM", flush=True)

    todo, skipped_empty, skipped_dynamic = [], [], []
    for g in groups:
        name = (g.get("name") or "").strip()
        if not name:
            continue
        if not (g.get("members") or 0):
            skipped_empty.append(name)
            continue
        if not args.include_dynamic and not g.get("static"):
            skipped_dynamic.append(f"{name} ({g.get('members')})")
            continue
        todo.append(g)

    if skipped_empty:
        print(f"  skipping {len(skipped_empty)} empty group(s): "
              f"{', '.join(sorted(skipped_empty))}")
    if skipped_dynamic:
        print(f"  skipping {len(skipped_dynamic)} dynamic group(s): "
              f"{', '.join(sorted(skipped_dynamic))}")
        print("    (rule-based in USM; use --include-dynamic to take them)")
    print(f"  {len(todo)} static group(s) with members to sync", flush=True)

    print("\nResolving membership...", flush=True)
    resolved = {}
    for g in todo:
        name = (g.get("name") or "").strip()
        # Use `name`, as levelblue_import.py does when writing findings. Matching
        # on fqdn would build groups that filter nothing.
        members = sorted({(a.get("name") or a.get("id") or "").strip()
                          for a in paginate(http, f"/api/2.0/assetGroups/{g['id']}/assets",
                                            "assets")} - {""})
        resolved[name] = dict(g=g, members=members)
        stated = g.get("members") or 0
        flag = "" if len(members) == stated else f"  (USM stated {stated})"
        print(f"  {name[:34]:36s} {len(members):>5} member(s){flag}", flush=True)

    print("\nApplying to RiskSentinel...", flush=True)
    added_groups = updated_groups = 0
    added_m = removed_m = 0
    collisions = []

    with app.app_context():
        for name, info in sorted(resolved.items()):
            g, members = info["g"], info["members"]
            existing = AssetGroup.query.filter_by(name=name).first()
            # AssetGroup.name is unique across the whole install rather than per
            # customer, so a name another customer already owns cannot be taken.
            if existing and existing.customer_id != cust_id:
                owner = Customer.query.get(existing.customer_id)
                collisions.append((name, owner.name if owner else "?"))
                continue

            if existing is None:
                existing = AssetGroup(
                    customer_id=cust_id, name=name,
                    description=(g.get("description")
                                 or f"Synced from USM ({'static' if g.get('static') else 'dynamic'} group)"),
                    color="#1f6feb")
                db.session.add(existing)
                db.session.flush()
                added_groups += 1
            else:
                updated_groups += 1
                if g.get("description"):
                    existing.description = g["description"]

            have = {m.asset_name for m in
                    AssetGroupMember.query.filter_by(group_id=existing.id)}
            want = set(members)
            for a in sorted(want - have):
                db.session.add(AssetGroupMember(group_id=existing.id, asset_name=a))
                added_m += 1
            if want - have:
                print(f"  {name[:30]:32s} +{len(want - have)} member(s)")
            gone = have - want
            if gone:
                (AssetGroupMember.query
                 .filter(AssetGroupMember.group_id == existing.id,
                         AssetGroupMember.asset_name.in_(list(gone)))
                 .delete(synchronize_session=False))
                removed_m += len(gone)
                print(f"  {name[:30]:32s} -{len(gone)} member(s) no longer in USM")

        stale = []
        if args.prune:
            names = set(resolved)
            for lg in AssetGroup.query.filter_by(customer_id=cust_id).all():
                if lg.name not in names:
                    stale.append(lg.name)
                    db.session.delete(lg)

        if args.dry_run:
            db.session.rollback()
            print("\n--dry-run: nothing written to the database.")
        else:
            db.session.commit()

    print(f"\n  groups created        {added_groups}")
    print(f"  groups updated        {updated_groups}")
    print(f"  members added         {added_m}")
    print(f"  members removed       {removed_m}")
    if args.prune:
        print(f"  local groups pruned   {len(stale)}"
              + (f"  ({', '.join(stale)})" if stale else ""))
    if collisions:
        print("\n  NOT synced, the name belongs to another customer:")
        for n, owner in collisions:
            print(f"    {n!r} is owned by {owner}")
        print("  AssetGroup.name is unique per install rather than per customer.")


if __name__ == "__main__":
    main()
