# Installing RiskSentinel on a new Mac

## 1. Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running
- This project folder copied to the new Mac (e.g. via `rsync`, AirDrop, or a tarball)

```bash
# from the old Mac
tar -czf risksentinel.tar.gz \
  --exclude='.venv' --exclude='instance' --exclude='uploads' --exclude='backups' \
  -C /Users/mynhardt/claude vuln-portal

# copy risksentinel.tar.gz to the new Mac, then:
tar -xzf risksentinel.tar.gz -C ~/claude
```

> Don't forget the credential files `.env.levelblue` and `.env.rapid7` — they're
> excluded from git but needed for the import scripts. Copy them across separately
> if they exist (`scp` or AirDrop), or recreate them from `.env.example`.

## 2. Configure environment

```bash
cd ~/claude/vuln-portal
cp .env.example .env
```

Edit `.env` and fill in:
- `SECRET_KEY` — generate a fresh one: `python3 -c "import secrets; print(secrets.token_hex(32))"`
- `LEVELBLUE_*` / `RAPID7_*` — only needed if you'll run the import scripts on this Mac

## 3. Build and start

```bash
docker compose -f docker-compose.prod.yml --env-file .env up -d --build
```

The `name: risksentinel` pin in both compose files keeps Docker volume names
(`risksentinel_vuln_data`, `risksentinel_vuln_uploads`) consistent regardless of
what the project folder is called — important for `backup.sh` / `restore.sh`.

First boot creates the SQLite schema, runs migrations, seeds a `Default` customer,
and creates the default admin: **admin / admin123** (change this immediately).

## 4. Restore data from the old Mac (optional)

If you took a backup with `backup.sh` on the old Mac:

```bash
# copy the backup tarball into ./backups/ on the new Mac, then:
./restore.sh backups/risksentinel_YYYYMMDD_HHMMSS.tar.gz
```

This stops the container, restores the SQLite DB + uploads into the
`risksentinel_*` volumes, and restarts it.

## 5. Reverse proxy / TLS (production)

If exposing this beyond localhost, put `nginx.conf` in front of it (HTTPS,
rate-limiting on `/login`, security headers, 50MB upload limit already configured).

## 6. Scheduled imports (optional)

Re-add cron jobs for `levelblue_import.py` / `rapid7_import.py` on the new Mac —
these run via `.venv` outside the container:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
# crontab -e
0 6 * * MON cd ~/claude/vuln-portal && .venv/bin/python levelblue_import.py --customer "Nebula"
0 6 * * MON cd ~/claude/vuln-portal && .venv/bin/python rapid7_import.py --customer "Europcar"
```
