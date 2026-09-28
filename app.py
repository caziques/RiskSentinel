import os
import sys
import json
import re
import threading
from datetime import datetime, date, timedelta
from functools import wraps, lru_cache

import time
import feedparser
import pandas as pd
from flask import (Flask, render_template, request, redirect, url_for,
                   flash, jsonify, abort, session)
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from sqlalchemy import func, desc, case, or_, and_
from werkzeug.utils import secure_filename

from models import db, User, Customer, UserCustomer, ScanImport, Vulnerability, NewsFeed, RiskAcceptance, AssetGroup, AssetGroupMember, RemediationProject, RemediationItem, RemediationSnapshot, SuppressionRule

__version__ = '4.17.3'

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-me-in-production-8f3k2j')
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(os.path.abspath('instance'), 'vuln_portal.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200MB

db.init_app(app)


# ── SQLite concurrency ───────────────────────────────────────────────────────
# The default rollback journal gives a writer an exclusive lock, so a bulk import
# stalls every reader: a 191k-row Cortex import made a simple count take over a
# second. WAL lets readers carry on while a write is in flight (measured at 3 ms
# against 1,043 ms), which matters because imports run while people are browsing.
#
# journal_mode is persisted in the database file; the rest are per-connection and
# so are set on every connect. Foreign-key enforcement is deliberately left off:
# turning it on now would be a behaviour change, not a concurrency fix.
from sqlalchemy import event as _sa_event
from sqlalchemy.engine import Engine as _SAEngine


@_sa_event.listens_for(_SAEngine, "connect")
def _set_sqlite_pragmas(dbapi_conn, _record):
    if 'sqlite3' not in type(dbapi_conn).__module__:
        return
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA synchronous=NORMAL")   # safe with WAL, much faster writes
    cur.execute("PRAGMA busy_timeout=15000")   # wait rather than fail under contention
    cur.execute("PRAGMA cache_size=-64000")    # 64 MB page cache, was 2 MB
    cur.execute("PRAGMA temp_store=MEMORY")
    cur.close()


@app.template_filter('fromjson')
def fromjson_filter(s):
    return json.loads(s) if s else []

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'warning'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('instance', exist_ok=True)


def _table_columns(conn, table):
    """Return the set of column names for a table (empty set if table doesn't exist)."""
    rows = conn.execute(db.text(f"PRAGMA table_info({table})")).fetchall()
    return {r[1] for r in rows}


def _run_migrations():
    """
    Safe, incremental schema migrations for SQLite.
    db.create_all() handles new tables; this handles new columns on existing tables.
    Add an entry here whenever a column is added to an existing model.
    """
    # (table, column, DDL type)
    COLUMN_MIGRATIONS = [
        # v3.0.0 — asset group risk acceptance scope
        ('risk_acceptances', 'group_id',     'INTEGER REFERENCES asset_groups(id)'),
        # v4.0.0 — multi-tenant customer columns
        ('scan_imports',     'customer_id',  'INTEGER REFERENCES customers(id)'),
        ('risk_acceptances', 'customer_id',  'INTEGER REFERENCES customers(id)'),
        ('asset_groups',     'customer_id',  'INTEGER REFERENCES customers(id)'),
        # v4.6.0 — NBL-IT-020 s14 auditable false positive suppression
        ('vulnerabilities',  'suppression_reason',     'TEXT'),
        ('vulnerabilities',  'suppressed_at',          'DATETIME'),
        ('vulnerabilities',  'suppressed_by_id',       'INTEGER REFERENCES users(id)'),
        ('vulnerabilities',  'suppression_review_due', 'DATETIME'),
        # v4.17.0 — per-customer scanner API config for the Update page
        ('customers',        'scanner',      'VARCHAR(32)'),
        ('customers',        'scanner_env',  'VARCHAR(128)'),
        ('customers',        'scanner_args', 'VARCHAR(256)'),
    ]

    # Composite indexes. Every hot query filters on (scan_import_id, suppressed)
    # and then groups, which single-column indexes serve poorly. Measured on a
    # 191k-row customer: severity counts 119ms -> 5ms, distinct assets 25ms -> 0ms,
    # distinct CVEs 55ms -> 5ms. The covering index carries the columns the
    # remediation aggregate reads, halving it from 164ms to 78ms.
    INDEX_MIGRATIONS = [
        ('ix_vuln_import_supp_sev',
         'vulnerabilities (scan_import_id, suppressed, risk_factor)'),
        ('ix_vuln_import_supp_asset',
         'vulnerabilities (scan_import_id, suppressed, asset)'),
        ('ix_vuln_import_supp_cve',
         'vulnerabilities (scan_import_id, suppressed, vulnerability_id)'),
        ('ix_vuln_remed_cover',
         'vulnerabilities (scan_import_id, suppressed, risk_factor, plugin_id, '
         'asset, cvss_v3_score, first_seen, last_seen)'),
    ]

    with db.engine.connect() as conn:
        for table, column, col_def in COLUMN_MIGRATIONS:
            cols = _table_columns(conn, table)
            if cols and column not in cols:
                conn.execute(db.text(
                    f"ALTER TABLE {table} ADD COLUMN {column} {col_def}"
                ))
                print(f'  [migrate] Added column {table}.{column}')

        existing = {r[0] for r in conn.execute(db.text(
            "SELECT name FROM sqlite_master WHERE type='index'")).all()}
        built = False
        for name, spec in INDEX_MIGRATIONS:
            if name not in existing:
                conn.execute(db.text(f'CREATE INDEX IF NOT EXISTS {name} ON {spec}'))
                print(f'  [migrate] Built index {name}')
                built = True
        if built:
            conn.execute(db.text('ANALYZE'))
        conn.commit()


def _seed_default_customer():
    """Create a 'Default' customer and assign all un-assigned data to it."""
    default = Customer.query.filter_by(name='Default').first()
    if not default:
        default = Customer(name='Default', active=True)
        db.session.add(default)
        db.session.flush()
        print('  [seed] Created default customer')

    cid = default.id
    # Back-fill existing rows that have no customer
    for model in (ScanImport, RiskAcceptance, AssetGroup):
        updated = (db.session.query(model)
                   .filter(model.customer_id.is_(None))
                   .update({'customer_id': cid}, synchronize_session=False))
        if updated:
            print(f'  [seed] Assigned {updated} {model.__tablename__} rows to Default customer')

    db.session.commit()


with app.app_context():
    db.create_all()
    _run_migrations()
    _seed_default_customer()


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.context_processor
def inject_version():
    return {'app_version': __version__}




def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated


def analyst_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ('admin', 'analyst'):
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ── Multi-tenant helpers ──────────────────────────────────────────────────────

def get_user_customers(user=None):
    """Return all Customer objects accessible to a user (all for admins)."""
    u = user or current_user
    if u.role == 'admin':
        return Customer.query.filter_by(active=True).order_by(Customer.name).all()
    return (Customer.query
            .join(UserCustomer, UserCustomer.customer_id == Customer.id)
            .filter(UserCustomer.user_id == u.id, Customer.active == True)
            .order_by(Customer.name).all())


def get_current_customer():
    """Return the Customer currently selected in the session, or None."""
    cid = session.get('customer_id')
    if not cid:
        return None
    cust = db.session.get(Customer, cid)
    if not cust or not cust.active:
        session.pop('customer_id', None)
        return None
    # Verify user still has access
    if current_user.role != 'admin':
        if not UserCustomer.query.filter_by(user_id=current_user.id, customer_id=cid).first():
            session.pop('customer_id', None)
            return None
    return cust


def customer_required(f):
    """Decorator: ensure a customer is selected in session before accessing data views."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not get_current_customer():
            return redirect(url_for('choose_customer', next=request.url))
        return f(*args, **kwargs)
    return decorated


@app.context_processor
def inject_customer():
    if current_user.is_authenticated:
        cust = get_current_customer()
        customers = get_user_customers() if current_user.is_authenticated else []
        return {'current_customer': cust, 'all_customers': customers}
    return {'current_customer': None, 'all_customers': []}


def _cust_scan_q():
    """ScanImport query scoped to the current customer."""
    cust = get_current_customer()
    q = ScanImport.query
    if cust:
        q = q.filter_by(customer_id=cust.id)
    return q


def _cust_ra_q():
    """RiskAcceptance query scoped to the current customer."""
    cust = get_current_customer()
    q = RiskAcceptance.query
    if cust:
        q = q.filter_by(customer_id=cust.id)
    return q


def _cust_ag_q():
    """AssetGroup query scoped to the current customer."""
    cust = get_current_customer()
    q = AssetGroup.query
    if cust:
        q = q.filter_by(customer_id=cust.id)
    return q


def _cust_rp_q():
    """RemediationProject query scoped to the current customer."""
    cust = get_current_customer()
    q = RemediationProject.query
    if cust:
        q = q.filter_by(customer_id=cust.id)
    return q


def _project_progress(project, live_counts=None):
    """
    Progress for a project.

    'resolved' counts items a human has closed or waived. 'verified' counts items
    whose plugin no longer appears in the current import, which is the scanner
    confirming the fix rather than someone asserting it. The two are reported
    separately on purpose: an item marked Closed that the scanner still sees is
    exactly the case worth surfacing.
    """
    items = list(project.items)
    total = len(items)
    done = sum(1 for i in items if i.is_done)
    waived = sum(1 for i in items if i.status == 'Will Not Fix')
    awaiting = sum(1 for i in items if i.status == 'Awaiting Verification')
    verified = disputed = 0
    if live_counts is not None:
        for i in items:
            still_present = live_counts.get(i.plugin_id, 0) > 0
            if not still_present:
                verified += 1
            elif i.status == 'Closed':
                disputed += 1
    return dict(
        total=total, done=done, waived=waived, awaiting=awaiting,
        open=total - done, verified=verified, disputed=disputed,
        pct=round(done / total * 100) if total else 0,
        verified_pct=round(verified / total * 100) if total else 0,
        hosts=sum(i.host_count or 0 for i in items),
        findings=sum(i.finding_count or 0 for i in items),
    )


def _record_snapshot(project, scan_import, prog, live):
    """
    Store this project's progress against the given import, once.

    Called on view rather than from the importers, so the scanner scripts stay
    unaware of projects. The unique constraint on (project, import) makes repeat
    views idempotent; an existing row is refreshed rather than duplicated so that
    status changes made later in the same scan cycle are not lost.
    """
    if not scan_import:
        return None
    snap = (RemediationSnapshot.query
            .filter_by(project_id=project.id, scan_import_id=scan_import.id).first())
    findings_open = sum(live.get(i.plugin_id, 0) for i in project.items if not i.is_done)
    fields = dict(
        report_date=scan_import.report_date,
        total_items=prog['total'], done_items=prog['done'],
        waived_items=prog['waived'], verified_items=prog['verified'],
        disputed_items=prog['disputed'], open_items=prog['open'],
        pct=prog['pct'], verified_pct=prog['verified_pct'],
        findings_open=findings_open,
    )
    if snap:
        for k, v in fields.items():
            setattr(snap, k, v)
    else:
        snap = RemediationSnapshot(project_id=project.id,
                                   scan_import_id=scan_import.id, **fields)
        db.session.add(snap)
    db.session.commit()
    return snap


def _active_suppression_rules(customer_id):
    return (SuppressionRule.query
            .filter_by(customer_id=customer_id, revoked=False)
            .all())


def apply_suppression_rules(customer_id, import_id=None):
    """
    Re-apply a customer's false-positive determinations to their findings.

    Called after every import, so a determination survives the next scan instead
    of lapsing silently. Also called when a rule is created, so it takes effect
    immediately on existing data. Returns the number of rows newly suppressed.
    """
    rules = _active_suppression_rules(customer_id)
    if not rules:
        return 0

    import_ids = [i.id for i in ScanImport.query.filter_by(customer_id=customer_id).all()] \
        if import_id is None else [import_id]
    if not import_ids:
        return 0

    now = datetime.utcnow()
    total = 0
    for rule in rules:
        q = (Vulnerability.query
             .filter(Vulnerability.scan_import_id.in_(import_ids),
                     Vulnerability.suppressed == False))
        if rule.scope == 'plugin' and rule.plugin_id:
            q = q.filter(Vulnerability.plugin_id == rule.plugin_id)
        elif rule.scope == 'asset' and rule.asset:
            q = q.filter(Vulnerability.asset == rule.asset)
        elif rule.scope == 'finding' and rule.plugin_id and rule.asset:
            q = q.filter(Vulnerability.plugin_id == rule.plugin_id,
                         Vulnerability.asset == rule.asset)
        else:
            continue

        n = q.update({'suppressed': True,
                      'suppression_reason': rule.reason,
                      'suppressed_at': now,
                      'suppressed_by_id': rule.created_by_id,
                      'suppression_review_due': rule.review_due},
                     synchronize_session=False)
        if n:
            total += n
        rule.last_applied = now
        rule.match_count = (rule.match_count or 0) + n
    db.session.commit()
    return total


def _live_plugin_counts(import_id, plugin_ids):
    """Findings still present per plugin in the given import."""
    if not import_id or not plugin_ids:
        return {}
    rows = (db.session.query(Vulnerability.plugin_id, func.count(Vulnerability.id))
            .filter(Vulnerability.scan_import_id == import_id,
                    Vulnerability.suppressed == False,
                    Vulnerability.plugin_id.in_(list(plugin_ids)))
            .group_by(Vulnerability.plugin_id).all())
    return {p: n for p, n in rows}


# ── CSV Parsing ──────────────────────────────────────────────────────────────

def parse_desc(val):
    try:
        s = str(val).strip()
        if s and s != 'nan':
            return json.loads(s)
    except Exception:
        pass
    return {}


def extract_port_from_text(text):
    """
    Try to extract a port number from free-text plugin output / description.
    Handles patterns like:
      'port 445', 'TCP port 443', 'ports 256, 257, and 258',
      'port 139 or 445', 'on port 3389'
    Returns the first valid port number as a string, or empty string.
    """
    if not text:
        return ''
    # Match 'port(s) <number>' optionally preceded by a protocol keyword
    m = re.search(r'\b(?:tcp|udp)?\s*port[s]?\s+(\d{1,5})\b', text, re.IGNORECASE)
    if m:
        return m.group(1)
    return ''


def parse_dt(val):
    s = str(val).strip()
    if not s or s == 'nan':
        return None
    for fmt in ('%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d'):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    return None


def parse_float(val):
    try:
        v = float(val)
        return v if v > 0 else None
    except Exception:
        return None


RISK_WEIGHT  = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1, 'Informational': 0}
VALID_SEV    = {'Critical', 'High', 'Medium', 'Low', 'Informational'}
SEV_LEVEL    = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Informational': 0}


def cvss_to_severity(score):
    """Derive a severity label from a CVSS v3 numeric score."""
    if not score:
        return None
    s = float(score)
    if s >= 9.0: return 'Critical'
    if s >= 7.0: return 'High'
    if s >= 4.0: return 'Medium'
    if s > 0:    return 'Low'
    return None


def resolve_severity(json_risk_factor, csv_v3_severity, cvss_v3_score, cvss_v4_score):
    """
    Authoritative severity, in priority order:
      1. CSV CVSS V3 Severity column (Tenable-calculated, most reliable)
      2. Derived from CVSS V3 score
      3. Derived from CVSS V4 score
      4. JSON risk_factor from plugin description
    Falls back to 'Informational' for truly informational items.
    """
    # 1. CSV column — only trust recognised values
    if csv_v3_severity and csv_v3_severity in VALID_SEV and csv_v3_severity != 'Informational':
        return csv_v3_severity
    # 2. Derive from CVSS V3 score
    derived = cvss_to_severity(cvss_v3_score)
    if derived:
        return derived
    # 3. Derive from CVSS V4 score
    derived = cvss_to_severity(cvss_v4_score)
    if derived:
        return derived
    # 4. JSON risk_factor
    if json_risk_factor in VALID_SEV:
        return json_risk_factor
    return 'Informational'


REQUIRED_COLUMNS = {'Vulnerability ID', 'Asset', 'Vulnerability Description'}

def import_csv(filepath, scan_import):
    df = pd.read_csv(filepath, dtype=str).fillna('')
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(
            f"Wrong CSV format — missing required columns: {', '.join(sorted(missing))}. "
            f"Please export the Vulnerabilities report from Tenable, not the Assets report."
        )
    records = []
    for _, row in df.iterrows():
        raw_desc_text = row.get('Vulnerability Description', '').strip()
        desc          = parse_desc(raw_desc_text)
        # Fallback: if JSON parse returned nothing, treat raw text as description
        is_plain_text = not desc and raw_desc_text

        cvss_v3_score    = parse_float(row.get('CVSS V3 Score', ''))
        cvss_v4_score    = parse_float(row.get('CVSS V4 Score', ''))
        csv_v3_severity  = row.get('CVSS V3 Severity', '').strip() or None
        json_risk_factor = desc.get('risk_factor', 'Informational') or 'Informational'

        risk_factor    = resolve_severity(json_risk_factor, csv_v3_severity, cvss_v3_score, cvss_v4_score)
        severity_level = SEV_LEVEL.get(risk_factor, 0)

        source     = row.get('Source', '').strip()
        plugin_name = desc.get('pluginName', '')

        records.append(Vulnerability(
            scan_import_id=scan_import.id,
            vulnerability_id=row.get('Vulnerability ID', '').strip(),
            suppressed=str(row.get('Suppressed', 'No')).strip().lower() == 'yes',
            asset=row.get('Asset', '').strip(),
            ip_address=row.get('Ip of the Assets', '').strip(),
            source=source,
            labels=row.get('Labels', '').strip(),
            first_seen=parse_dt(row.get('First Seen ISO 8601', '')),
            last_seen=parse_dt(row.get('Last Seen ISO 8601', '')),
            cvss_v3_severity=csv_v3_severity,
            cvss_v3_score=cvss_v3_score,
            cvss_v4_severity=row.get('CVSS V4 Severity', '').strip() or None,
            cvss_v4_score=cvss_v4_score,
            available_patches=row.get('Available Patches', '').strip() or None,
            affected_software=row.get('Affected Software', '').strip() or None,
            plugin_id=desc.get('pluginID', ''),
            plugin_name=plugin_name,
            plugin_family=desc.get('pluginFamily', ''),
            risk_factor=risk_factor,
            severity_level=severity_level,
            synopsis=desc.get('synopsis', ''),
            description=desc.get('description', '') or (raw_desc_text if is_plain_text else ''),
            solution=desc.get('solution', ''),
            port=desc.get('port', '') or extract_port_from_text(desc.get('plugin_output', '') or raw_desc_text),
            protocol=desc.get('protocol', ''),
            plugin_output=desc.get('plugin_output', ''),
            cpe=desc.get('cpe', ''),
        ))

    db.session.bulk_save_objects(records)
    db.session.commit()
    return len(records)


def _risk_score_expr():
    return func.sum(case(
        (Vulnerability.risk_factor == 'Critical', 10),
        (Vulnerability.risk_factor == 'High', 7),
        (Vulnerability.risk_factor == 'Medium', 4),
        (Vulnerability.risk_factor == 'Low', 1),
        else_=0
    ))


def _sev_count(sev):
    return func.sum(case((Vulnerability.risk_factor == sev, 1), else_=0))


def _latest_import():
    return _cust_scan_q().order_by(desc(ScanImport.imported_at)).first()


def _fetch_active_ras():
    """Return active (non-revoked, non-expired) RiskAcceptance records for current customer."""
    now = datetime.utcnow()
    return _cust_ra_q().filter_by(revoked=False).filter(
        or_(RiskAcceptance.expires_at == None, RiskAcceptance.expires_at > now)
    ).all()


def _ra_criteria(active_ras):
    """
    From a list of RiskAcceptance records build two sets for efficient filtering:
      excl_assets  : set of asset names (whole-asset scope, group scope, or finding scope with no plugin)
      excl_findings: set of (asset, plugin_id) tuples (finding scope with a specific plugin)
    """
    excl_assets   = set()
    excl_findings = set()
    for ra in active_ras:
        if ra.scope == 'group' and ra.group_id:
            members = AssetGroupMember.query.filter_by(group_id=ra.group_id).all()
            for m in members:
                excl_assets.add(m.asset_name)
        elif ra.scope == 'asset' and ra.asset:
            excl_assets.add(ra.asset)
        elif ra.scope == 'finding' and ra.asset:
            if ra.plugin_id:
                excl_findings.add((ra.asset, ra.plugin_id))
            else:
                excl_assets.add(ra.asset)
    return excl_assets, excl_findings


def _apply_ra_filter(q, excl_assets, excl_findings):
    """Apply accepted-risk exclusion filters to a SQLAlchemy query."""
    if excl_assets:
        q = q.filter(~Vulnerability.asset.in_(list(excl_assets)))
    if excl_findings:
        conditions = [and_(Vulnerability.asset == a, Vulnerability.plugin_id == p)
                      for a, p in excl_findings]
        q = q.filter(~or_(*conditions))
    return q


def _accepted_vuln_ids(import_id, active_ras=None):
    """Return set of Vulnerability.id values covered by active risk acceptances."""
    if active_ras is None:
        active_ras = _fetch_active_ras()
    if not active_ras:
        return set()
    excl_assets, excl_findings = _ra_criteria(active_ras)
    excluded = set()
    if excl_assets:
        rows = (db.session.query(Vulnerability.id)
                .filter_by(scan_import_id=import_id)
                .filter(Vulnerability.asset.in_(list(excl_assets))).all())
        excluded.update(r[0] for r in rows)
    if excl_findings:
        conditions = [and_(Vulnerability.asset == a, Vulnerability.plugin_id == p)
                      for a, p in excl_findings]
        rows = (db.session.query(Vulnerability.id)
                .filter_by(scan_import_id=import_id)
                .filter(or_(*conditions)).all())
        excluded.update(r[0] for r in rows)
    return excluded


# ── Auth ─────────────────────────────────────────────────────────────────────

@app.route('/')
@login_required
def index():
    return redirect(url_for('executive'))


@app.route('/changelog')
@login_required
def changelog():
    changelog_path = os.path.join(os.path.dirname(__file__), 'CHANGELOG.md')
    try:
        with open(changelog_path, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        content = ''
    # Parse into releases: list of {version, date, sections: [{title, items}]}
    releases = []
    current = None
    current_section = None
    for line in content.splitlines():
        # Accept an em-dash or a plain hyphen between version and date.
        m = re.match(r'^## \[(.+?)\]\s*[—-]\s*(.+)', line)
        if m:
            if current:
                if current_section:
                    current['sections'].append(current_section)
                releases.append(current)
            current = {'version': m.group(1), 'date': m.group(2), 'sections': []}
            current_section = None
        elif line.startswith('### ') and current is not None:
            if current_section:
                current['sections'].append(current_section)
            current_section = {'title': line[4:], 'entries': []}
        elif line.startswith('- ') and current_section is not None:
            current_section['entries'].append(line[2:])
    if current:
        if current_section:
            current['sections'].append(current_section)
        releases.append(current)
    return render_template('changelog.html', releases=releases, current_version=__version__)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('choose_customer'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username, is_active=True).first()
        if user and user.check_password(password):
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user, remember=bool(request.form.get('remember')))
            return redirect(url_for('choose_customer'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    session.pop('customer_id', None)
    logout_user()
    return redirect(url_for('login'))


# ── Customer chooser ──────────────────────────────────────────────────────────

@app.route('/choose-customer')
@login_required
def choose_customer():
    customers = get_user_customers()
    if not customers:
        flash('You have no customers assigned. Ask an administrator.', 'warning')
        return render_template('choose_customer.html', customers=[])
    # Auto-select if only one
    if len(customers) == 1:
        session['customer_id'] = customers[0].id
        return redirect(request.args.get('next') or url_for('executive'))
    return render_template('choose_customer.html', customers=customers)


@app.route('/switch-customer/<int:customer_id>')
@login_required
def switch_customer(customer_id):
    customers = get_user_customers()
    if any(c.id == customer_id for c in customers):
        session['customer_id'] = customer_id
    else:
        flash('Access denied to that customer.', 'danger')
    return redirect(request.args.get('next') or url_for('executive'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_pw = request.form.get('current_password', '')
        new_pw = request.form.get('new_password', '')
        if not current_user.check_password(current_pw):
            flash('Current password is incorrect.', 'danger')
        elif len(new_pw) < 6:
            flash('New password must be at least 6 characters.', 'danger')
        else:
            current_user.set_password(new_pw)
            db.session.commit()
            flash('Password updated.', 'success')
    return render_template('profile.html')


# ── Dashboard ────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
@customer_required
def dashboard():
    import_id = request.args.get('import_id', type=int)
    latest = _latest_import()
    if not latest:
        return render_template('dashboard.html', no_data=True)

    # Allow switching scan via query param
    from models import ScanImport as SI
    current_import = (db.session.get(SI, import_id) if import_id else latest) or latest

    q = Vulnerability.query.filter_by(scan_import_id=current_import.id)
    total = q.count()
    suppressed_count = q.filter_by(suppressed=True).count()
    active = total - suppressed_count

    sev_rows = (db.session.query(Vulnerability.risk_factor, func.count(Vulnerability.id))
                .filter_by(scan_import_id=current_import.id)
                .group_by(Vulnerability.risk_factor).all())
    sev = {k: 0 for k in ('Critical', 'High', 'Medium', 'Low', 'Informational')}
    for rf, cnt in sev_rows:
        if rf in sev:
            sev[rf] = cnt

    # Week-over-week delta vs previous import
    prev = (_cust_scan_q()
            .filter(ScanImport.imported_at < current_import.imported_at)
            .order_by(desc(ScanImport.imported_at)).first())
    delta = {}
    if prev:
        prev_ids  = {v.vulnerability_id for v in
                     Vulnerability.query.filter_by(scan_import_id=prev.id)
                     .with_entities(Vulnerability.vulnerability_id)}
        cur_ids   = {v.vulnerability_id for v in
                     Vulnerability.query.filter_by(scan_import_id=current_import.id)
                     .with_entities(Vulnerability.vulnerability_id)}
        delta = {'new': len(cur_ids - prev_ids), 'resolved': len(prev_ids - cur_ids)}

    top_assets = (db.session.query(
        Vulnerability.asset,
        Vulnerability.ip_address,
        func.count(Vulnerability.id).label('total'),
        _risk_score_expr().label('risk_score'),
        _sev_count('Critical').label('critical'),
        _sev_count('High').label('high'),
        _sev_count('Medium').label('medium'),
        _sev_count('Low').label('low'),
    ).filter_by(scan_import_id=current_import.id)
     .group_by(Vulnerability.asset)
     .order_by(desc('risk_score'))
     .limit(10).all())

    top_vulns = (db.session.query(
        Vulnerability.plugin_id,
        Vulnerability.plugin_name,
        Vulnerability.risk_factor,
        func.count(Vulnerability.id).label('cnt')
    ).filter(
        Vulnerability.scan_import_id == current_import.id,
        Vulnerability.risk_factor.in_(['Critical', 'High', 'Medium'])
    ).group_by(Vulnerability.plugin_name)
     .order_by(desc('cnt'))
     .limit(10).all())

    # Trend — include import_id so JS can link clicks
    trend_imports = _cust_scan_q().order_by(ScanImport.imported_at).all()
    trend_data = []
    for imp in trend_imports:
        label = imp.report_date.isoformat() if imp.report_date else imp.imported_at.strftime('%Y-%m-%d')
        row = {'date': label, 'import_id': imp.id}
        for s in ('Critical', 'High', 'Medium', 'Low'):
            row[s] = Vulnerability.query.filter_by(scan_import_id=imp.id, risk_factor=s).count()
        trend_data.append(row)

    all_imports    = _cust_scan_q().order_by(desc(ScanImport.imported_at)).all()
    recent_imports = all_imports[:5]

    # Assets chart data for JS
    assets_chart = [{'asset': a.asset, 'risk_score': float(a.risk_score or 0),
                     'critical': a.critical, 'high': a.high, 'medium': a.medium}
                    for a in top_assets]

    return render_template('dashboard.html',
                           no_data=False,
                           latest=current_import,
                           total=total, active=active, suppressed_count=suppressed_count,
                           sev=sev, delta=delta,
                           top_assets=top_assets,
                           top_vulns=top_vulns,
                           trend_data=json.dumps(trend_data),
                           assets_chart_json=json.dumps(assets_chart),
                           all_imports=all_imports,
                           recent_imports=recent_imports)


@app.route('/api/dashboard/vulns')
@login_required
@customer_required
def api_dashboard_vulns():
    """AJAX endpoint — returns filtered vulnerability rows for the drill-down drawer."""
    import_id  = request.args.get('import_id', type=int)
    severity   = request.args.get('severity', '')
    suppressed = request.args.get('suppressed', 'false')
    asset      = request.args.get('asset', '')
    plugin_id  = request.args.get('plugin_id', '')

    q = Vulnerability.query
    if import_id:
        q = q.filter_by(scan_import_id=import_id)
    if severity:
        q = q.filter_by(risk_factor=severity)
    if suppressed == 'true':
        q = q.filter_by(suppressed=True)
    elif suppressed == 'false':
        q = q.filter_by(suppressed=False)
    if asset:
        q = q.filter_by(asset=asset)
    if plugin_id:
        q = q.filter_by(plugin_id=plugin_id)

    total = q.count()
    items = (q.order_by(desc(Vulnerability.severity_level), desc(Vulnerability.cvss_v3_score))
              .limit(30).all())

    return jsonify({
        'total': total,
        'items': [{
            'id':          v.id,
            'asset':       v.asset,
            'ip':          v.ip_address,
            'plugin_name': v.plugin_name,
            'plugin_id':   v.plugin_id,
            'risk_factor': v.risk_factor,
            'cvss3':       v.cvss_v3_score,
            'first_seen':  v.first_seen.strftime('%Y-%m-%d') if v.first_seen else None,
            'days_open':   (datetime.utcnow() - v.first_seen).days if v.first_seen else None,
        } for v in items]
    })


# ── Vulnerabilities ───────────────────────────────────────────────────────────

@app.route('/vulnerabilities')
@login_required
@customer_required
def vulnerabilities():
    import_id = request.args.get('import_id', type=int)
    severity = request.args.get('severity', '')
    asset_filter = request.args.get('asset', '')
    show_suppressed = request.args.get('suppressed', 'false')
    search = request.args.get('search', '').strip()
    exclude_accepted = request.args.get('exclude_accepted', '0') == '1'
    page = request.args.get('page', 1, type=int)

    latest = _latest_import()
    if not import_id and latest:
        import_id = latest.id

    all_imports = _cust_scan_q().order_by(desc(ScanImport.imported_at)).all()

    q = Vulnerability.query
    if import_id:
        q = q.filter_by(scan_import_id=import_id)
    if severity:
        q = q.filter_by(risk_factor=severity)
    if asset_filter:
        q = q.filter(Vulnerability.asset.ilike(f'%{asset_filter}%'))
    if show_suppressed == 'false':
        q = q.filter_by(suppressed=False)
    elif show_suppressed == 'true':
        q = q.filter_by(suppressed=True)
    if search:
        q = q.filter(or_(
            Vulnerability.plugin_name.ilike(f'%{search}%'),
            Vulnerability.asset.ilike(f'%{search}%'),
            Vulnerability.ip_address.ilike(f'%{search}%'),
            Vulnerability.synopsis.ilike(f'%{search}%'),
            Vulnerability.vulnerability_id.ilike(f'%{search}%'),
            Vulnerability.cpe.ilike(f'%{search}%'),
        ))
    if exclude_accepted:
        active_ras = _fetch_active_ras()
        excl_assets, excl_findings = _ra_criteria(active_ras)
        q = _apply_ra_filter(q, excl_assets, excl_findings)
        accepted_count = len(_accepted_vuln_ids(import_id, active_ras)) if import_id else 0
    else:
        accepted_count = 0

    total = q.count()
    pagination = q.order_by(desc(Vulnerability.severity_level), desc(Vulnerability.cvss_v3_score)).paginate(
        page=page, per_page=100, error_out=False)

    return render_template('vulnerabilities.html',
                           vulns=pagination.items,
                           pagination=pagination,
                           total=total,
                           all_imports=all_imports,
                           current_import_id=import_id,
                           severity=severity,
                           asset_filter=asset_filter,
                           show_suppressed=show_suppressed,
                           search=search,
                           exclude_accepted=exclude_accepted,
                           accepted_count=accepted_count)


@app.route('/vulnerabilities/<int:vuln_id>')
@login_required
@customer_required
def vulnerability_detail(vuln_id):
    vuln = db.get_or_404(Vulnerability, vuln_id)
    similar = (Vulnerability.query
               .filter(Vulnerability.plugin_id == vuln.plugin_id,
                       Vulnerability.id != vuln.id,
                       Vulnerability.scan_import_id == vuln.scan_import_id)
               .limit(20).all())
    # History is per scan, not per finding. One row per occurrence made a single
    # Cortex import look like 52 separate scans, because a CVE there repeats for
    # every affected host and package. Aggregate to one row per import.
    # Scoped to this customer: unscoped, a CVE present in more than one tenant
    # listed all of their occurrences here.
    hist_import_ids = [i.id for i in _cust_scan_q().all()]
    history = []
    if hist_import_ids:
        rows = (db.session.query(
                    Vulnerability.scan_import_id.label('import_id'),
                    func.min(Vulnerability.first_seen).label('first_seen'),
                    func.max(Vulnerability.last_seen).label('last_seen'),
                    func.max(Vulnerability.severity_level).label('worst'),
                    func.count(Vulnerability.id).label('findings'),
                    func.count(func.distinct(Vulnerability.asset)).label('assets'))
                .filter(Vulnerability.vulnerability_id == vuln.vulnerability_id,
                        Vulnerability.scan_import_id.in_(hist_import_ids))
                .group_by(Vulnerability.scan_import_id).all())
        imports_by_id = {i.id: i for i in _cust_scan_q().all()}
        lvl_name = {4: 'Critical', 3: 'High', 2: 'Medium', 1: 'Low', 0: 'Informational'}
        history = sorted(
            [dict(scan_import=imports_by_id.get(r.import_id),
                  first_seen=r.first_seen, last_seen=r.last_seen,
                  risk_factor=lvl_name.get(r.worst, 'Informational'),
                  findings=r.findings, assets=r.assets)
             for r in rows if imports_by_id.get(r.import_id)],
            key=lambda h: (h['scan_import'].imported_at or datetime.min))
    # How many other live findings share this detection, for the suppress dialog.
    sibling_count = 0
    if vuln.plugin_id and hist_import_ids:
        sibling_count = (db.session.query(func.count(Vulnerability.id))
                         .filter(Vulnerability.plugin_id == vuln.plugin_id,
                                 Vulnerability.suppressed == False,
                                 Vulnerability.scan_import_id.in_(hist_import_ids))
                         .scalar()) or 0

    return render_template('vulnerability_detail.html', vuln=vuln, similar=similar,
                           history=history, sibling_count=sibling_count,
                           now=datetime.utcnow())


# ── Assets ────────────────────────────────────────────────────────────────────

@app.route('/assets')
@login_required
@customer_required
def assets():
    import_id = request.args.get('import_id', type=int)
    search = request.args.get('search', '').strip()

    latest = _latest_import()
    if not import_id and latest:
        import_id = latest.id

    all_imports = _cust_scan_q().order_by(desc(ScanImport.imported_at)).all()

    q = Vulnerability.query
    if import_id:
        q = q.filter_by(scan_import_id=import_id)
    if search:
        q = q.filter(or_(
            Vulnerability.asset.ilike(f'%{search}%'),
            Vulnerability.ip_address.ilike(f'%{search}%'),
        ))

    asset_data = (q.with_entities(
        Vulnerability.asset,
        Vulnerability.ip_address,
        func.count(Vulnerability.id).label('total'),
        _risk_score_expr().label('risk_score'),
        _sev_count('Critical').label('critical'),
        _sev_count('High').label('high'),
        _sev_count('Medium').label('medium'),
        _sev_count('Low').label('low'),
        _sev_count('Informational').label('info'),
    ).group_by(Vulnerability.asset)
     .order_by(desc('risk_score'))
     .all())

    # Build a map: asset_name → list of (group_id, group_name, group_color)
    _ag_ids = [g.id for g in _cust_ag_q().with_entities(AssetGroup.id)]
    all_members = AssetGroupMember.query.filter(AssetGroupMember.group_id.in_(_ag_ids)).all() if _ag_ids else []
    asset_group_map = {}
    for m in all_members:
        asset_group_map.setdefault(m.asset_name, []).append(m.group)

    return render_template('assets.html',
                           assets=asset_data,
                           all_imports=all_imports,
                           current_import_id=import_id,
                           search=search,
                           asset_group_map=asset_group_map)


@app.route('/assets/<path:asset_name>')
@login_required
@customer_required
def asset_detail(asset_name):
    import_id = request.args.get('import_id', type=int)
    latest = _latest_import()
    if not import_id and latest:
        import_id = latest.id

    all_imports = _cust_scan_q().order_by(desc(ScanImport.imported_at)).all()
    vulns = (Vulnerability.query
             .filter_by(asset=asset_name, scan_import_id=import_id)
             .order_by(desc(Vulnerability.severity_level), desc(Vulnerability.cvss_v3_score))
             .all())

    sev = {k: 0 for k in ('Critical', 'High', 'Medium', 'Low', 'Informational')}
    for v in vulns:
        if v.risk_factor in sev:
            sev[v.risk_factor] += 1

    # Week-over-week history for this asset
    hist = (db.session.query(
        ScanImport.imported_at,
        ScanImport.report_date,
        func.count(Vulnerability.id).label('total'),
        _sev_count('Critical').label('critical'),
        _sev_count('High').label('high'),
        _sev_count('Medium').label('medium'),
    ).join(Vulnerability)
     .filter(Vulnerability.asset == asset_name)
     .group_by(ScanImport.id)
     .order_by(ScanImport.imported_at)
     .all())

    history_data = [{
        'date': (h.report_date.isoformat() if h.report_date else h.imported_at.strftime('%Y-%m-%d')),
        'total': h.total, 'critical': h.critical, 'high': h.high, 'medium': h.medium,
    } for h in hist]

    # Families breakdown
    families = [(row[0], row[1]) for row in
                db.session.query(Vulnerability.plugin_family, func.count(Vulnerability.id).label('cnt'))
                .filter_by(asset=asset_name, scan_import_id=import_id)
                .group_by(Vulnerability.plugin_family)
                .order_by(desc('cnt')).all()]

    asset_groups = (_cust_ag_q()
                    .join(AssetGroupMember)
                    .filter(AssetGroupMember.asset_name == asset_name)
                    .order_by(AssetGroup.name).all())

    return render_template('asset_detail.html',
                           asset_name=asset_name,
                           vulns=vulns,
                           sev=sev,
                           all_imports=all_imports,
                           current_import_id=import_id,
                           history_data=json.dumps(history_data),
                           families=families,
                           asset_groups=asset_groups)


# ── Trends ────────────────────────────────────────────────────────────────────

@app.route('/trends')
@login_required
@customer_required
def trends():
    imports = _cust_scan_q().order_by(ScanImport.imported_at).all()
    import_ids = [i.id for i in imports]

    # One grouped query for the whole series rather than five counts per import.
    SEV_ORDER = ('Critical', 'High', 'Medium', 'Low', 'Informational')
    counts = {}
    if import_ids:
        for iid, rf, n in (db.session.query(Vulnerability.scan_import_id,
                                            Vulnerability.risk_factor,
                                            func.count(Vulnerability.id))
                           .filter(Vulnerability.scan_import_id.in_(import_ids))
                           .group_by(Vulnerability.scan_import_id,
                                     Vulnerability.risk_factor).all()):
            counts[(iid, rf)] = n
    trend_data = []
    for imp in imports:
        label = imp.report_date.isoformat() if imp.report_date else imp.imported_at.strftime('%Y-%m-%d')
        row = {'date': label, 'total': imp.record_count or 0}
        for sv in SEV_ORDER:
            row[sv] = counts.get((imp.id, sv), 0)
        trend_data.append(row)

    # Plugin families. Scoped to this customer's imports: without the filter these
    # aggregated across every tenant, so each customer saw the largest customer's
    # data on their own trends page.
    families = []
    recurring = []
    if import_ids:
        families = [(r[0], r[1]) for r in
                    db.session.query(Vulnerability.plugin_family,
                                     func.count(Vulnerability.id).label('cnt'))
                    .filter(Vulnerability.scan_import_id.in_(import_ids))
                    .group_by(Vulnerability.plugin_family)
                    .order_by(desc('cnt')).limit(12).all()]

        # Most persistent vulnerabilities, by how many of this customer's imports
        # they appear in.
        recurring = (db.session.query(
            Vulnerability.plugin_name,
            Vulnerability.plugin_id,
            Vulnerability.risk_factor,
            func.count(Vulnerability.scan_import_id.distinct()).label('weeks'),
            func.count(Vulnerability.asset.distinct()).label('assets'),
        ).filter(Vulnerability.scan_import_id.in_(import_ids))
         .group_by(Vulnerability.plugin_id)
         .having(func.count(Vulnerability.scan_import_id.distinct()) > 0)
         .order_by(desc('weeks'), desc('assets'))
         .limit(25).all())

    # New vs existing comparison (last 2 imports)
    all_imports_list = _cust_scan_q().order_by(desc(ScanImport.imported_at)).limit(2).all()
    new_this_week = resolved_this_week = 0
    if len(all_imports_list) >= 2:
        cur_ids = set(v.vulnerability_id for v in
                      Vulnerability.query.filter_by(scan_import_id=all_imports_list[0].id)
                      .with_entities(Vulnerability.vulnerability_id).all())
        prev_ids = set(v.vulnerability_id for v in
                       Vulnerability.query.filter_by(scan_import_id=all_imports_list[1].id)
                       .with_entities(Vulnerability.vulnerability_id).all())
        new_this_week = len(cur_ids - prev_ids)
        resolved_this_week = len(prev_ids - cur_ids)

    return render_template('trends.html',
                           trend_data=json.dumps(trend_data),
                           families=families,
                           families_json=json.dumps([{'family': f, 'count': c} for f, c in families]),
                           recurring=recurring,
                           imports=imports,
                           new_this_week=new_this_week,
                           resolved_this_week=resolved_this_week)


# ── Import ────────────────────────────────────────────────────────────────────

@app.route('/import', methods=['GET', 'POST'])
@login_required
@analyst_required
@customer_required
def import_scan():
    if request.method == 'POST':
        if 'file' not in request.files or not request.files['file'].filename:
            flash('No file selected.', 'danger')
            return redirect(request.url)

        f = request.files['file']
        if not f.filename.lower().endswith('.csv'):
            flash('Only CSV files are accepted.', 'danger')
            return redirect(request.url)

        filename = secure_filename(f.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        f.save(filepath)

        report_date = date.today()
        m = re.search(r'(\d{4}-\d{2}-\d{2})', filename)
        if m:
            try:
                report_date = date.fromisoformat(m.group(1))
            except ValueError:
                pass

        cust = get_current_customer()
        scan = ScanImport(filename=filename, report_date=report_date,
                          customer_id=cust.id if cust else None,
                          imported_by_id=current_user.id,
                          notes=request.form.get('notes', ''))
        db.session.add(scan)
        db.session.flush()

        try:
            count = import_csv(filepath, scan)
            scan.record_count = count
            db.session.commit()
            flash(f'Successfully imported {count:,} vulnerabilities from {filename}.', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Import failed: {e}', 'danger')
            return redirect(request.url)

    recent = _cust_scan_q().order_by(desc(ScanImport.imported_at)).limit(10).all()
    return render_template('import.html', recent=recent,
                           cust=get_current_customer())


@app.route('/import/<int:import_id>/delete', methods=['POST'])
@login_required
@admin_required
@customer_required
def delete_import(import_id):
    scan = db.get_or_404(ScanImport, import_id)
    name = scan.filename
    db.session.delete(scan)
    db.session.commit()
    flash(f'Deleted import "{name}".', 'success')
    return redirect(url_for('import_scan'))


# ── Remediation ───────────────────────────────────────────────────────────────

SEVERITY_WEIGHT = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1, 'Informational': 0}
SLA_DAYS        = {'Critical': 7, 'High': 30, 'Medium': 90, 'Low': 180}

# NBL-IT-020 section 19.2: a risk acceptance shall not exceed 90 days.
MAX_RA_DAYS = 90

# NBL-IT-020 section 14: suppressions are reviewed at least every six months.
SUPPRESSION_REVIEW_DAYS = 182

# NBL-IT-020 section 11: internet-facing systems carry shorter remediation windows
# than internal ones. Critical is 48 hours, expressed here in whole days.
SLA_DAYS_INTERNET = {'Critical': 2, 'High': 15, 'Medium': 30, 'Low': 90}

# Membership of this asset group marks an asset as internet-facing.
INTERNET_FACING_GROUP = 'Internet-Facing'


def _internet_facing_assets():
    """
    Asset names carrying the internet-facing SLA tier for the current customer.

    Exposure is driven by membership of the 'Internet-Facing' asset group, so the
    tier is maintained through the existing Asset Groups screen rather than a
    separate mechanism. Returns an empty set when the group does not exist, in
    which case every asset falls back to the internal tier.
    """
    grp = _cust_ag_q().filter(AssetGroup.name == INTERNET_FACING_GROUP).first()
    if not grp:
        return set()
    return {m.asset_name for m in
            AssetGroupMember.query.filter_by(group_id=grp.id).all()}


def _sla_for(risk_factor, asset, ext_assets):
    """Remediation window in days for a finding, per NBL-IT-020 section 11."""
    if ext_assets and asset in ext_assets:
        return SLA_DAYS_INTERNET.get(risk_factor)
    return SLA_DAYS.get(risk_factor)


def _remediation_rows(import_id, include_info=False, include_suppressed=False):
    """Return sorted, enriched plugin rows for the remediation engine."""
    filters = [Vulnerability.scan_import_id == import_id]
    if not include_suppressed:
        filters.append(Vulnerability.suppressed == False)
    if not include_info:
        filters.append(Vulnerability.risk_factor != 'Informational')

    agg = db.session.query(
        Vulnerability.plugin_id,
        Vulnerability.plugin_name,
        Vulnerability.plugin_family,
        Vulnerability.risk_factor,
        Vulnerability.solution,
        func.max(Vulnerability.cvss_v3_score).label('cvss3'),
        func.max(Vulnerability.cvss_v4_score).label('cvss4'),
        func.count(Vulnerability.asset.distinct()).label('host_count'),
        func.count(Vulnerability.id).label('finding_count'),
        func.min(Vulnerability.first_seen).label('first_seen'),
        func.max(Vulnerability.last_seen).label('last_seen'),
    ).filter(*filters).group_by(Vulnerability.plugin_id).all()

    # Plugin rows span many assets. Where any affected asset is internet-facing the
    # stricter tier applies to the group, so the row is not reported as compliant
    # while an exposed host is still outstanding (NBL-IT-020 section 11).
    ext_assets = _internet_facing_assets()
    ext_plugins = set()
    if ext_assets:
        ext_plugins = {
            p for (p,) in db.session.query(Vulnerability.plugin_id)
            .filter(*filters)
            .filter(Vulnerability.asset.in_(list(ext_assets)))
            .distinct().all()
        }

    now = datetime.utcnow()
    rows = []
    for r in agg:
        cvss      = float(r.cvss3) if r.cvss3 else None
        weight    = SEVERITY_WEIGHT.get(r.risk_factor, 0)
        base      = cvss if cvss else weight
        risk_score = round(base * r.host_count, 1)
        days_open  = (now - r.first_seen).days if r.first_seen else None
        sla        = (SLA_DAYS_INTERNET.get(r.risk_factor)
                      if r.plugin_id in ext_plugins
                      else SLA_DAYS.get(r.risk_factor))
        sla_breach = (days_open is not None and sla is not None and days_open > sla)
        sol        = (r.solution or '').strip()
        has_sol    = bool(sol) and sol.lower() not in ('n/a', 'n/a.', 'none', '')
        effort     = ('single' if r.host_count == 1
                      else 'few' if r.host_count <= 5
                      else 'org-wide')
        rows.append(dict(
            plugin_id=r.plugin_id,
            plugin_name=r.plugin_name or r.plugin_id or 'Unknown',
            plugin_family=r.plugin_family, risk_factor=r.risk_factor,
            solution=sol, cvss3=cvss,
            host_count=r.host_count, finding_count=r.finding_count,
            risk_score=risk_score, has_solution=has_sol,
            days_open=days_open, sla_breach=sla_breach, effort=effort,
            risk_pct=0.0, cumulative_pct=0.0, rank=0,
        ))

    rows.sort(key=lambda x: (-x['risk_score'], -x['host_count']))
    total_risk = sum(r['risk_score'] for r in rows) or 1
    cumulative = 0.0
    for i, r in enumerate(rows):
        cumulative      += r['risk_score']
        r['risk_pct']    = round(r['risk_score'] / total_risk * 100, 2)
        r['cumulative_pct'] = round(cumulative / total_risk * 100, 1)
        r['rank']        = i + 1
    return rows, round(total_risk, 1)


@app.route('/remediation')
@login_required
@customer_required
def remediation():
    import_id        = request.args.get('import_id', type=int)
    include_info     = request.args.get('include_info', '0') == '1'
    include_suppressed = request.args.get('include_suppressed', '0') == '1'
    # The table is a prioritisation ranking, so only the top slice is rendered.
    # Large estates produce tens of thousands of solutions; sending them all put
    # 50 MB into the DOM and hung the browser. Aggregates below still use the
    # full set, so KPIs and percentages stay correct.
    ROW_LIMITS = (100, 250, 500, 1000)
    row_limit = request.args.get('limit', type=int)
    if row_limit not in ROW_LIMITS and row_limit != 0:
        row_limit = 250

    latest = _latest_import()
    if not import_id and latest:
        import_id = latest.id

    all_imports = _cust_scan_q().order_by(desc(ScanImport.imported_at)).all()
    rows, total_risk = _remediation_rows(import_id, include_info, include_suppressed)

    # Also get info-only count for the toggle hint
    info_count = (db.session.query(func.count(Vulnerability.plugin_id.distinct()))
                  .filter_by(scan_import_id=import_id, risk_factor='Informational', suppressed=False)
                  .scalar() or 0)

    # ── KPIs ──────────────────────────────────────────────────────────────────
    total_plugins   = len(rows)
    sla_breaches    = sum(1 for r in rows if r['sla_breach'])
    with_solution   = sum(1 for r in rows if r['has_solution'])
    ch_count        = sum(1 for r in rows if r['risk_factor'] in ('Critical','High'))
    top10_pct       = rows[9]['cumulative_pct'] if len(rows) >= 10 else (rows[-1]['cumulative_pct'] if rows else 0)
    top20_pct       = rows[19]['cumulative_pct'] if len(rows) >= 20 else (rows[-1]['cumulative_pct'] if rows else 0)

    # ── Age buckets ───────────────────────────────────────────────────────────
    age_buckets = {'<7d': 0, '7–30d': 0, '30–90d': 0, '>90d': 0}
    for r in rows:
        d = r['days_open']
        if d is None: continue
        if d < 7:    age_buckets['<7d']   += 1
        elif d < 30: age_buckets['7–30d'] += 1
        elif d < 90: age_buckets['30–90d']+= 1
        else:        age_buckets['>90d']  += 1

    # ── Effort buckets ────────────────────────────────────────────────────────
    effort_counts = {'single': 0, 'few': 0, 'org-wide': 0}
    for r in rows:
        effort_counts[r['effort']] += 1

    # ── Solution grouping ─────────────────────────────────────────────────────
    sol_map = {}
    for r in rows:
        if not r['has_solution']:
            continue
        key = r['solution'][:150]
        if key not in sol_map:
            sol_map[key] = {'solution': r['solution'], 'plugins': [],
                             'total_risk': 0.0, 'families': set(), 'severities': set()}
        g = sol_map[key]
        g['plugins'].append(r)
        g['total_risk'] += r['risk_score']
        g['families'].add(r['plugin_family'])
        g['severities'].add(r['risk_factor'])

    solution_groups = sorted(
        [{'solution': v['solution'],
          'plugin_count': len(v['plugins']),
          'total_risk': round(v['total_risk'], 1),
          'risk_pct': round(v['total_risk'] / total_risk * 100, 1),
          'families': sorted(v['families'])[:4],
          'top_severity': max(v['severities'], key=lambda s: SEVERITY_WEIGHT.get(s, 0)),
          'preview': v['plugins'][:4]}
         for v in sol_map.values() if len(v['plugins']) >= 1],
        key=lambda x: -x['total_risk']
    )[:15]

    # ── Chart payloads ────────────────────────────────────────────────────────
    cumulative_chart = [{'x': r['rank'], 'y': r['cumulative_pct'], 'label': r['plugin_name']}
                        for r in rows[:60]]

    # Cap the bubble chart too: beyond a few hundred points it is unreadable and
    # the JSON payload alone runs to megabytes.
    SCATTER_CAP = 400
    scatter_data = [{'x': r['host_count'],
                     'y': round(r['cvss3'] or SEVERITY_WEIGHT.get(r['risk_factor'], 0), 1),
                     'r': max(5, min(28, r['finding_count'] // max(1, r['host_count']) + 5)),
                     'name': r['plugin_name'], 'id': r['plugin_id'],
                     'sev': r['risk_factor'], 'risk': r['risk_score']}
                    for r in rows[:SCATTER_CAP] if r['risk_score'] > 0]

    sev_bar = {s: sum(1 for r in rows if r['risk_factor'] == s)
               for s in ('Critical', 'High', 'Medium', 'Low', 'Informational')}

    open_projects = (_cust_rp_q().filter(RemediationProject.status == 'Open')
                     .order_by(RemediationProject.name).all())
    shown_rows = rows if row_limit == 0 else rows[:row_limit]
    return render_template('remediation.html',
        open_projects=open_projects,
        rows=shown_rows, total_rows=len(rows),
        row_limit=row_limit, row_limits=ROW_LIMITS,
        scatter_cap=SCATTER_CAP,
        total_risk=total_risk,
        total_plugins=total_plugins, sla_breaches=sla_breaches,
        with_solution=with_solution, ch_count=ch_count,
        top10_pct=top10_pct, top20_pct=top20_pct,
        info_count=info_count, include_info=include_info,
        include_suppressed=include_suppressed,
        age_buckets=age_buckets, effort_counts=effort_counts,
        solution_groups=solution_groups,
        all_imports=all_imports, current_import_id=import_id,
        cumulative_chart_json=json.dumps(cumulative_chart),
        scatter_json=json.dumps(scatter_data),
        age_json=json.dumps(age_buckets),
        effort_json=json.dumps(effort_counts),
        sev_bar_json=json.dumps(sev_bar),
    )


# ── SLA / Age Tracking ────────────────────────────────────────────────────────

@app.route('/sla')
@login_required
@customer_required
def sla_tracking():
    import_id       = request.args.get('import_id', type=int)
    severity_filter = request.args.get('severity', '')
    status_filter   = request.args.get('status', '')   # breached / at_risk / on_track
    exclude_accepted = request.args.get('exclude_accepted', '0') == '1'

    latest = _latest_import()
    if not latest:
        return render_template('sla.html', no_data=True)

    current_import = (db.session.get(ScanImport, import_id) if import_id else latest) or latest
    now = datetime.utcnow()

    # All active findings with a known severity
    # Select columns, not entities. Materialising 191k full ORM objects to read
    # eight fields cost about 2.9 s on the largest customer; lightweight rows do
    # the same work far faster and attribute access is unchanged.
    vq = (db.session.query(
              Vulnerability.id, Vulnerability.asset, Vulnerability.ip_address,
              Vulnerability.plugin_id, Vulnerability.plugin_name,
              Vulnerability.risk_factor, Vulnerability.cvss_v3_score,
              Vulnerability.first_seen)
          .filter(Vulnerability.scan_import_id == current_import.id,
                  Vulnerability.suppressed == False,
                  Vulnerability.risk_factor.in_(['Critical', 'High', 'Medium', 'Low'])))
    if exclude_accepted:
        active_ras = _fetch_active_ras()
        excl_assets, excl_findings = _ra_criteria(active_ras)
        vq = _apply_ra_filter(vq, excl_assets, excl_findings)
        accepted_count = len(_accepted_vuln_ids(current_import.id, active_ras))
    else:
        accepted_count = 0
    all_vulns = vq.all()

    # Internet-facing assets carry the shorter SLA tier (NBL-IT-020 section 11)
    ext_assets = _internet_facing_assets()

    # Annotate each finding with age / SLA status
    AT_RISK_BUFFER = 7   # days before SLA deadline that counts as "at risk"
    findings = []
    for v in all_vulns:
        days_open = (now - v.first_seen).days if v.first_seen else None
        is_ext    = v.asset in ext_assets
        sla       = _sla_for(v.risk_factor, v.asset, ext_assets)
        if days_open is None or sla is None:
            status = 'N/A'
            days_overdue = None
        elif days_open > sla:
            status = 'Breached'
            days_overdue = days_open - sla
        elif days_open >= sla - AT_RISK_BUFFER:
            status = 'At Risk'
            days_overdue = 0
        else:
            status = 'On Track'
            days_overdue = None
        findings.append(dict(
            id=v.id, asset=v.asset, ip=v.ip_address,
            plugin_id=v.plugin_id, plugin_name=v.plugin_name,
            risk_factor=v.risk_factor, cvss3=v.cvss_v3_score,
            first_seen=v.first_seen, days_open=days_open,
            sla_days=sla, status=status, days_overdue=days_overdue,
            internet_facing=is_ext,
        ))

    # KPIs
    total    = len(findings)
    breached = sum(1 for f in findings if f['status'] == 'Breached')
    at_risk  = sum(1 for f in findings if f['status'] == 'At Risk')
    on_track = sum(1 for f in findings if f['status'] == 'On Track')
    ages     = [f['days_open'] for f in findings if f['days_open'] is not None]
    avg_age  = round(sum(ages) / len(ages)) if ages else 0
    max_age  = max(ages) if ages else 0

    # Age distribution stacked bar (buckets × severity)
    SEVS          = ['Critical', 'High', 'Medium', 'Low']
    # Ageing bands per NBL-IT-020 section 18
    bucket_ranges = [(0, 7), (8, 30), (31, 60), (61, 90), (91, 99999)]
    bucket_labels = ['0 to 7 days', '8 to 30 days', '31 to 60 days', '61 to 90 days', 'Over 90 days']
    age_dist = {s: [0] * 5 for s in SEVS}
    for f in findings:
        if f['days_open'] is None:
            continue
        for i, (lo, hi) in enumerate(bucket_ranges):
            if lo <= f['days_open'] <= hi:
                if f['risk_factor'] in age_dist:
                    age_dist[f['risk_factor']][i] += 1
                break

    # SLA compliance per severity
    sla_compliance = {}
    for sev in SEVS:
        sf = [f for f in findings if f['risk_factor'] == sev]
        n  = len(sf) or 1
        br = sum(1 for f in sf if f['status'] == 'Breached')
        ar = sum(1 for f in sf if f['status'] == 'At Risk')
        ok = sum(1 for f in sf if f['status'] == 'On Track')
        sf_ages = [f['days_open'] for f in sf if f['days_open'] is not None]
        sla_compliance[sev] = dict(
            total=len(sf), breached=br, at_risk=ar, on_track=ok,
            sla_days=SLA_DAYS[sev],
            sla_days_ext=SLA_DAYS_INTERNET[sev],
            ext_count=sum(1 for f in sf if f['internet_facing']),
            compliance_pct=round(ok / n * 100),
            avg_age=round(sum(sf_ages) / len(sf_ages)) if sf_ages else 0,
            max_age=max(sf_ages) if sf_ages else 0,
        )

    # Age trend — avg age at scan time for last 12 imports
    trend_imports = _cust_scan_q().order_by(ScanImport.imported_at).all()[-12:]
    age_trend = []
    for imp in trend_imports:
        ref = datetime(imp.report_date.year, imp.report_date.month, imp.report_date.day) \
              if imp.report_date else imp.imported_at
        label = imp.report_date.isoformat() if imp.report_date else imp.imported_at.strftime('%Y-%m-%d')
        row = {'date': label, 'import_id': imp.id}
        # Average age is computed in SQL. Loading every finding as an ORM entity
        # just to average a date difference was the single biggest cost on this
        # page: four severities times twelve imports, 191k objects built and
        # thrown away. julianday() gives the same answer in one grouped query.
        avg_rows = (db.session.query(
                        Vulnerability.risk_factor,
                        # CAST truncates each row to whole days before averaging,
                        # matching Python's timedelta.days. Averaging the raw
                        # fractions instead shifted some figures by a day.
                        func.avg(func.cast(
                            func.julianday(ref) - func.julianday(Vulnerability.first_seen),
                            db.Integer)))
                    .filter(Vulnerability.scan_import_id == imp.id,
                            Vulnerability.suppressed == False,
                            Vulnerability.risk_factor.in_(SEVS),
                            Vulnerability.first_seen.isnot(None))
                    .group_by(Vulnerability.risk_factor).all())
        avg_by_sev = {rf: days for rf, days in avg_rows}
        for sev in SEVS:
            d = avg_by_sev.get(sev)
            row[sev] = round(d) if d is not None else None
        age_trend.append(row)

    # Apply filters and sort for table
    filtered = findings[:]
    if severity_filter:
        filtered = [f for f in filtered if f['risk_factor'] == severity_filter]
    status_map = {'breached': 'Breached', 'at_risk': 'At Risk', 'on_track': 'On Track'}
    if status_filter and status_filter in status_map:
        filtered = [f for f in filtered if f['status'] == status_map[status_filter]]

    STATUS_ORDER = {'Breached': 0, 'At Risk': 1, 'On Track': 2, 'N/A': 3}
    filtered.sort(key=lambda f: (STATUS_ORDER.get(f['status'], 4), -(f['days_open'] or 0)))

    all_imports = _cust_scan_q().order_by(desc(ScanImport.imported_at)).all()

    return render_template('sla.html',
        no_data=False,
        latest=current_import,
        all_imports=all_imports,
        current_import_id=current_import.id,
        total=total, breached=breached, at_risk=at_risk, on_track=on_track,
        avg_age=avg_age, max_age=max_age,
        sla_compliance=sla_compliance,
        sla_days=SLA_DAYS,
        age_dist_json=json.dumps({'labels': bucket_labels, 'data': age_dist}),
        age_trend_json=json.dumps(age_trend),
        findings=filtered[:500],
        severity_filter=severity_filter,
        status_filter=status_filter,
        exclude_accepted=exclude_accepted,
        accepted_count=accepted_count,
        sla_days_ext=SLA_DAYS_INTERNET,
        ext_asset_count=len(ext_assets),
    )


@app.route('/sla/export-csv')
@login_required
@customer_required
def sla_export_csv():
    import csv, io
    import_id = request.args.get('import_id', type=int)
    exclude_accepted = request.args.get('exclude_accepted', '0') == '1'
    latest = _latest_import()
    if not latest:
        return ('No data', 404)
    current_import = (db.session.get(ScanImport, import_id) if import_id else latest) or latest
    now = datetime.utcnow()

    vq = (db.session.query(
              Vulnerability.asset, Vulnerability.ip_address,
              Vulnerability.plugin_id, Vulnerability.plugin_name,
              Vulnerability.vulnerability_id, Vulnerability.risk_factor,
              Vulnerability.cvss_v3_score, Vulnerability.first_seen)
          .filter(Vulnerability.scan_import_id == current_import.id,
                  Vulnerability.suppressed == False,
                  Vulnerability.risk_factor.in_(['Critical', 'High', 'Medium', 'Low'])))
    if exclude_accepted:
        excl_assets, excl_findings = _ra_criteria(_fetch_active_ras())
        vq = _apply_ra_filter(vq, excl_assets, excl_findings)
    all_vulns = vq.all()

    ext_assets = _internet_facing_assets()

    rows = []
    for v in all_vulns:
        days_open = (now - v.first_seen).days if v.first_seen else None
        sla = _sla_for(v.risk_factor, v.asset, ext_assets)
        if days_open is not None and sla is not None and days_open > sla:
            rows.append({
                'Status':       'Breached',
                'Asset':        v.asset or '',
                'IP Address':   v.ip_address or '',
                'Exposure':     'Internet-facing' if v.asset in ext_assets else 'Internal',
                'Plugin':       v.plugin_name or v.plugin_id or v.vulnerability_id or '',
                'Severity':     v.risk_factor or '',
                'CVSS':         v.cvss_v3_score if v.cvss_v3_score is not None else '',
                'First Seen':   v.first_seen.strftime('%Y-%m-%d') if v.first_seen else '',
                'Age (days)':   days_open,
                'SLA (days)':   sla,
                'Overdue by':   days_open - sla,
            })

    rows.sort(key=lambda r: (-r['Overdue by'], r['Severity'], r['Asset']))

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()) if rows else [
        'Status','Asset','IP Address','Exposure','Plugin','Severity','CVSS','First Seen','Age (days)','SLA (days)','Overdue by'
    ])
    writer.writeheader()
    writer.writerows(rows)

    cust = get_current_customer()
    cust_name = cust.name.replace(' ', '_') if cust else 'export'
    date_str = datetime.utcnow().strftime('%Y-%m-%d')
    filename = f'SLA-Breached-{cust_name}-{date_str}.csv'

    from flask import Response
    return Response(
        buf.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


# ── Scanner API updates ──────────────────────────────────────────────────────
# Imports take minutes, so a request cannot wait for one. The job runs as a
# subprocess, exactly as the weekly cron does, and the page polls for progress.
# Running it in-process would mean two SQLAlchemy sessions writing the same
# SQLite file from one interpreter, which is precisely what WAL is not for.

_api_jobs = {}          # customer_id -> job dict
_api_jobs_lock = threading.Lock()


def _api_job_state(customer_id):
    with _api_jobs_lock:
        job = _api_jobs.get(customer_id)
        return dict(job) if job else None


def _run_api_import(customer_id, customer_name, script, env_file, extra_args, started_by):
    """Run a scanner importer and record progress. Executed on a worker thread."""
    import subprocess
    cmd = [sys.executable, os.path.join(APP_ROOT, script), '--customer', customer_name]
    if env_file:
        cmd += ['--env-file', env_file]
    if extra_args:
        cmd += extra_args.split()
    cmd += ['--notes', f'Manual API update from the portal ({started_by})']

    with _api_jobs_lock:
        _api_jobs[customer_id] = dict(
            state='running', started=datetime.utcnow(), finished=None,
            customer=customer_name, script=script, started_by=started_by,
            lines=[], summary='', returncode=None)

    try:
        proc = subprocess.Popen(cmd, cwd=APP_ROOT, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in proc.stdout:
            line = line.rstrip()
            if not line or 'Deprecat' in line:
                continue
            with _api_jobs_lock:
                j = _api_jobs.get(customer_id)
                if j is not None:
                    j['lines'].append(line)
                    del j['lines'][:-200]          # keep the tail only
        proc.wait()
        rc = proc.returncode
    except Exception as e:
        with _api_jobs_lock:
            j = _api_jobs.get(customer_id)
            if j is not None:
                j.update(state='failed', finished=datetime.utcnow(),
                         summary=f'{type(e).__name__}: {e}', returncode=-1)
        return

    with _api_jobs_lock:
        j = _api_jobs.get(customer_id)
        if j is None:
            return
        done = [l for l in j['lines'] if l.startswith('Done')]
        j.update(state='finished' if rc == 0 else 'failed',
                 finished=datetime.utcnow(), returncode=rc,
                 summary=(done[-1] if done else
                          (j['lines'][-1] if j['lines'] else 'No output')))


@app.route('/import/api', methods=['POST'])
@login_required
@analyst_required
@customer_required
def import_api():
    cust = get_current_customer()
    if not cust:
        flash('Choose a customer first.', 'danger')
        return redirect(url_for('import_scan'))
    if not cust.can_api_update:
        flash(f'No scanner API is configured for {cust.name}. An administrator '
              f'can set one under Admin > Customers.', 'warning')
        return redirect(url_for('import_scan'))

    running = _api_job_state(cust.id)
    if running and running['state'] == 'running':
        flash('An update is already running for this customer.', 'warning')
        return redirect(url_for('import_scan'))

    t = threading.Thread(
        target=_run_api_import,
        args=(cust.id, cust.name, cust.scanner_script, cust.scanner_env,
              cust.scanner_args, current_user.username),
        daemon=True)
    t.start()
    flash(f'{cust.scanner_label} update started. Progress appears below; it is '
          f'safe to leave this page.', 'success')
    return redirect(url_for('import_scan'))


@app.route('/import/api/status')
@login_required
@customer_required
def import_api_status():
    cust = get_current_customer()
    job = _api_job_state(cust.id) if cust else None
    if not job:
        return jsonify(state='idle')
    return jsonify(
        state=job['state'],
        summary=job['summary'],
        lines=job['lines'][-25:],
        started=job['started'].strftime('%H:%M:%S') if job['started'] else None,
        finished=job['finished'].strftime('%H:%M:%S') if job['finished'] else None,
        started_by=job['started_by'],
        returncode=job['returncode'],
    )


# ── Update from Git ──────────────────────────────────────────────────────────

DEFAULT_GIT_REMOTE = os.environ.get(
    'GIT_REMOTE_URL', 'https://github.com/caziques/RiskSentinel.git')
APP_ROOT = os.path.dirname(os.path.abspath(__file__))


def _git(*args, timeout=120):
    """Run a git command in the application directory. Returns (ok, output)."""
    import subprocess
    try:
        r = subprocess.run(('git',) + args, cwd=APP_ROOT, capture_output=True,
                           text=True, timeout=timeout)
        out = (r.stdout or '') + (r.stderr or '')
        return r.returncode == 0, out.strip()
    except FileNotFoundError:
        return False, 'git is not installed on this host.'
    except subprocess.TimeoutExpired:
        return False, f'git {args[0]} timed out after {timeout}s.'
    except Exception as e:
        return False, f'{type(e).__name__}: {e}'


def _git_status():
    """Current repository state, or why it cannot be read."""
    st = {'is_repo': False, 'remote': '', 'branch': '', 'commit': '', 'subject': '',
          'when': '', 'dirty': [], 'behind': 0, 'ahead': 0, 'error': '',
          'in_container': False, 'remedy': ''}

    # A container running code baked into an image is the common case, and
    # "not a git repository" alone is true but useless: the remedy differs from
    # a bare-metal install, so report which situation this actually is.
    st['in_container'] = os.path.exists('/.dockerenv')

    ok, _ = _git('rev-parse', '--is-inside-work-tree')
    if not ok:
        if st['in_container']:
            st['error'] = ('This container runs code built into its image, so it '
                           'cannot update itself in place.')
            st['remedy'] = 'container'
        else:
            st['error'] = 'This installation is not a git repository, so it cannot self-update.'
            st['remedy'] = 'adopt'
        return st
    st['is_repo'] = True

    ok, out = _git('remote', 'get-url', 'origin')
    st['remote'] = out if ok else ''
    ok, out = _git('rev-parse', '--abbrev-ref', 'HEAD')
    st['branch'] = out if ok else ''
    ok, out = _git('log', '-1', '--pretty=%h|%s|%cr')
    if ok and '|' in out:
        st['commit'], st['subject'], st['when'] = (out.split('|', 2) + ['', ''])[:3]

    # Uncommitted local edits. Updating over these would discard work.
    ok, out = _git('status', '--porcelain')
    if ok and out:
        st['dirty'] = [l.strip() for l in out.splitlines() if l.strip()][:40]

    ok, out = _git('rev-list', '--left-right', '--count', f'HEAD...origin/{st["branch"]}')
    if ok and out:
        parts = out.split()
        if len(parts) == 2:
            st['ahead'], st['behind'] = int(parts[0]), int(parts[1])
    return st


@app.route('/admin/update')
@login_required
@customer_required
def admin_update():
    if current_user.role != 'admin':
        flash('Only administrators may manage updates.', 'danger')
        return redirect(url_for('executive'))
    st = _git_status()
    incoming = []
    if st['is_repo'] and st['behind']:
        ok, out = _git('log', '--pretty=%h|%s|%an|%cr',
                       f'HEAD..origin/{st["branch"]}', '-30')
        if ok and out:
            for line in out.splitlines():
                bits = line.split('|')
                if len(bits) >= 4:
                    incoming.append(dict(sha=bits[0], subject=bits[1],
                                         author=bits[2], when=bits[3]))
    return render_template('admin_update.html', st=st, incoming=incoming,
                           default_remote=DEFAULT_GIT_REMOTE, version=__version__)


@app.route('/admin/update/check', methods=['POST'])
@login_required
@customer_required
def admin_update_check():
    """Fetch from the remote so the page can report what is waiting."""
    if current_user.role != 'admin':
        flash('Only administrators may manage updates.', 'danger')
        return redirect(url_for('executive'))

    remote = (request.form.get('remote') or '').strip() or DEFAULT_GIT_REMOTE
    ok, _ = _git('rev-parse', '--is-inside-work-tree')
    if not ok:
        flash('This installation is not a git repository.', 'danger')
        return redirect(url_for('admin_update'))

    cur_ok, cur = _git('remote', 'get-url', 'origin')
    if not cur_ok:
        _git('remote', 'add', 'origin', remote)
    elif cur.strip() != remote:
        _git('remote', 'set-url', 'origin', remote)
        flash(f'Remote set to {remote}', 'info')

    ok, out = _git('fetch', 'origin', '--prune', timeout=180)
    flash('Checked for updates.' if ok else f'Fetch failed: {out[:300]}',
          'success' if ok else 'danger')
    return redirect(url_for('admin_update'))


@app.route('/admin/update/pull', methods=['POST'])
@login_required
@customer_required
def admin_update_pull():
    """
    Fast-forward onto the remote branch.

    Refuses when the working tree is dirty: pulling over local edits would
    discard them silently. Data lives in instance/ and uploads/ and the
    credential files, all of which are gitignored, so an update never touches
    customer data. A restart is still required for code changes to take effect.
    """
    if current_user.role != 'admin':
        flash('Only administrators may manage updates.', 'danger')
        return redirect(url_for('executive'))

    st = _git_status()
    if not st['is_repo']:
        flash('This installation is not a git repository.', 'danger')
        return redirect(url_for('admin_update'))
    if st['dirty']:
        flash(f'{len(st["dirty"])} uncommitted local change(s). Commit or discard '
              f'them before updating, so nothing is lost.', 'danger')
        return redirect(url_for('admin_update'))
    if not st['behind']:
        flash('Already up to date.', 'info')
        return redirect(url_for('admin_update'))

    before = st['commit']
    ok, out = _git('merge', '--ff-only', f'origin/{st["branch"]}', timeout=180)
    if not ok:
        flash(f'Update failed, nothing changed: {out[:400]}', 'danger')
        return redirect(url_for('admin_update'))

    after = _git_status()['commit']
    flash(f'Updated from {before} to {after}. Restart the application for the '
          f'changes to take effect.', 'success')
    return redirect(url_for('admin_update'))


# ── Remediation Projects ─────────────────────────────────────────────────────

@app.route('/projects')
@login_required
@customer_required
def projects():
    status = request.args.get('status', '')
    q = _cust_rp_q()
    if status == 'open':
        q = q.filter(RemediationProject.status == 'Open')
    elif status == 'closed':
        q = q.filter(RemediationProject.status == 'Closed')
    rows = q.order_by(desc(RemediationProject.created_at)).all()

    latest = _latest_import()
    cards = []
    for pr in rows:
        pids = [i.plugin_id for i in pr.items if i.plugin_id]
        live = _live_plugin_counts(latest.id if latest else None, pids)
        cards.append(dict(p=pr, prog=_project_progress(pr, live)))

    counts = dict(
        all=len(rows),
        open=sum(1 for c in cards if c['p'].display_status == 'Open'),
        expired=sum(1 for c in cards if c['p'].display_status == 'Expired'),
        closed=sum(1 for c in cards if c['p'].display_status == 'Closed'),
    )
    return render_template('projects.html', cards=cards, counts=counts,
                           status=status, today=datetime.utcnow().date())


@app.route('/projects/create', methods=['POST'])
@login_required
@customer_required
def project_create():
    name = request.form.get('name', '').strip()
    if not name:
        flash('A project name is required.', 'danger')
        return redirect(url_for('projects'))

    due_str = request.form.get('due_date', '').strip()
    due = None
    if due_str:
        try:
            due = datetime.strptime(due_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Due date could not be read.', 'danger')
            return redirect(url_for('projects'))

    owner_id = request.form.get('owner_id', type=int)
    cust = get_current_customer()
    latest = _latest_import()
    pr = RemediationProject(
        customer_id=cust.id if cust else None,
        name=name,
        description=request.form.get('description', '').strip() or None,
        project_type='dynamic' if request.form.get('project_type') == 'dynamic' else 'static',
        due_date=due,
        owner_id=owner_id or None,
        created_by_id=current_user.id,
        source_import_id=latest.id if latest else None,
    )
    db.session.add(pr)
    db.session.flush()

    added = _add_plugins_to_project(pr, request.form.getlist('plugin_ids'))
    db.session.commit()
    flash(f'Project <strong>{pr.name}</strong> created with {added} solution(s).', 'success')
    return redirect(url_for('project_detail', project_id=pr.id))


def _add_plugins_to_project(pr, plugin_ids):
    """Attach solutions to a project, skipping any already present."""
    plugin_ids = [p for p in plugin_ids if p]
    if not plugin_ids:
        return 0
    latest = _latest_import()
    if not latest:
        return 0
    existing = {i.plugin_id for i in pr.items}
    rows, _total = _remediation_rows(latest.id)
    by_plugin = {r['plugin_id']: r for r in rows}
    added = 0
    for pid in plugin_ids:
        if pid in existing:
            continue
        r = by_plugin.get(pid)
        if not r:
            continue
        db.session.add(RemediationItem(
            project_id=pr.id, plugin_id=pid,
            plugin_name=r.get('plugin_name'), risk_factor=r.get('risk_factor'),
            cvss_score=r.get('cvss3'), solution=r.get('solution'),
            host_count=r.get('host_count') or 0,
            finding_count=r.get('finding_count') or 0,
        ))
        added += 1
    return added


@app.route('/projects/<int:project_id>')
@login_required
@customer_required
def project_detail(project_id):
    pr = _cust_rp_q().filter(RemediationProject.id == project_id).first() or abort(404)
    latest = _latest_import()

    # Dynamic projects absorb newly discovered work on solutions already in scope.
    if pr.project_type == 'dynamic' and pr.status == 'Open' and latest:
        refreshed = 0
        _rr, _tr = _remediation_rows(latest.id)
        rows = {r['plugin_id']: r for r in _rr}
        for i in pr.items:
            r = rows.get(i.plugin_id)
            if r and (r.get('host_count') or 0) > (i.host_count or 0):
                i.host_count = r['host_count']
                i.finding_count = r.get('finding_count') or i.finding_count
                refreshed += 1
        if refreshed:
            db.session.commit()

    items = pr.items.order_by(desc(RemediationItem.cvss_score)).all()
    live = _live_plugin_counts(latest.id if latest else None,
                               [i.plugin_id for i in items if i.plugin_id])
    prog = _project_progress(pr, live)
    _record_snapshot(pr, latest, prog, live)

    # Solutions the scanner no longer sees but nobody has closed yet.
    verifiable = [i for i in items
                  if live.get(i.plugin_id, 0) == 0 and i.status != 'Closed'
                  and i.status != 'Will Not Fix']

    history = (pr.snapshots.join(ScanImport,
                                 RemediationSnapshot.scan_import_id == ScanImport.id)
               .order_by(ScanImport.imported_at).all())
    trend = [{'date': (h.report_date.isoformat() if h.report_date
                       else h.taken_at.strftime('%Y-%m-%d')),
              'pct': h.pct, 'verified_pct': h.verified_pct,
              'open': h.open_items, 'findings': h.findings_open}
             for h in history]

    users = User.query.filter_by(is_active=True).order_by(User.username).all()
    return render_template('project_detail.html', p=pr, items=items, prog=prog,
                           live=live, users=users, latest=latest,
                           verifiable=verifiable,
                           trend_json=json.dumps(trend), trend_points=len(trend),
                           statuses=RemediationItem.STATUSES,
                           today=datetime.utcnow().date())


@app.route('/projects/<int:project_id>/items/<int:item_id>/update', methods=['POST'])
@login_required
@customer_required
def project_item_update(project_id, item_id):
    pr = _cust_rp_q().filter(RemediationProject.id == project_id).first() or abort(404)
    item = pr.items.filter(RemediationItem.id == item_id).first() or abort(404)

    new_status = request.form.get('status', '').strip()
    if new_status and new_status in RemediationItem.STATUSES:
        item.status = new_status
    if 'assignee_id' in request.form:
        aid = request.form.get('assignee_id', type=int)
        item.assignee_id = aid or None
    if 'notes' in request.form:
        item.notes = request.form.get('notes', '').strip() or None
    item.updated_at = datetime.utcnow()
    item.updated_by_id = current_user.id
    db.session.commit()

    if _wants_json():
        return jsonify(ok=True, status=item.status,
                       assignee=item.assignee.username if item.assignee else None)
    flash('Solution updated.', 'success')
    return redirect(url_for('project_detail', project_id=pr.id))


@app.route('/projects/<int:project_id>/close-verified', methods=['POST'])
@login_required
@customer_required
def project_close_verified(project_id):
    """
    Close every solution the latest scan no longer detects.

    Deliberately a prompted action rather than something applied automatically:
    absence from one scan is strong evidence but not proof, and closing a finding
    is a decision someone should own.
    """
    pr = _cust_rp_q().filter(RemediationProject.id == project_id).first() or abort(404)
    latest = _latest_import()
    items = pr.items.all()
    live = _live_plugin_counts(latest.id if latest else None,
                               [i.plugin_id for i in items if i.plugin_id])
    closed = 0
    for i in items:
        if i.status in ('Closed', 'Will Not Fix'):
            continue
        if live.get(i.plugin_id, 0) == 0:
            i.status = 'Closed'
            i.updated_at = datetime.utcnow()
            i.updated_by_id = current_user.id
            note = f"Closed on scanner verification ({latest.filename})" if latest else "Closed on scanner verification"
            i.notes = f"{i.notes}\n{note}" if i.notes else note
            closed += 1
    db.session.commit()
    flash(f'{closed} solution(s) closed on scanner verification.' if closed
          else 'Nothing to close: every outstanding solution is still detected.',
          'success' if closed else 'warning')
    return redirect(url_for('project_detail', project_id=pr.id))


@app.route('/projects/<int:project_id>/items/add', methods=['POST'])
@login_required
@customer_required
def project_items_add(project_id):
    pr = _cust_rp_q().filter(RemediationProject.id == project_id).first() or abort(404)
    added = _add_plugins_to_project(pr, request.form.getlist('plugin_ids'))
    db.session.commit()
    flash(f'{added} solution(s) added.' if added else 'Nothing added.',
          'success' if added else 'warning')
    return redirect(url_for('project_detail', project_id=pr.id))


@app.route('/projects/<int:project_id>/items/<int:item_id>/remove', methods=['POST'])
@login_required
@customer_required
def project_item_remove(project_id, item_id):
    pr = _cust_rp_q().filter(RemediationProject.id == project_id).first() or abort(404)
    item = pr.items.filter(RemediationItem.id == item_id).first() or abort(404)
    db.session.delete(item)
    db.session.commit()
    flash('Solution removed from project.', 'warning')
    return redirect(url_for('project_detail', project_id=pr.id))


@app.route('/projects/<int:project_id>/close', methods=['POST'])
@login_required
@customer_required
def project_close(project_id):
    pr = _cust_rp_q().filter(RemediationProject.id == project_id).first() or abort(404)
    if pr.status == 'Open':
        pr.status = 'Closed'
        pr.closed_at = datetime.utcnow()
        pr.closed_by_id = current_user.id
        flash(f'Project {pr.name} closed.', 'success')
    else:
        pr.status = 'Open'
        pr.closed_at = None
        pr.closed_by_id = None
        flash(f'Project {pr.name} reopened.', 'success')
    db.session.commit()
    return redirect(url_for('project_detail', project_id=pr.id))


@app.route('/projects/<int:project_id>/delete', methods=['POST'])
@login_required
@customer_required
def project_delete(project_id):
    pr = _cust_rp_q().filter(RemediationProject.id == project_id).first() or abort(404)
    if current_user.role != 'admin':
        flash('Only administrators may delete a project.', 'danger')
        return redirect(url_for('project_detail', project_id=pr.id))
    name = pr.name
    db.session.delete(pr)
    db.session.commit()
    flash(f'Project {name} deleted.', 'warning')
    return redirect(url_for('projects'))


@app.route('/projects/<int:project_id>/export-csv')
@login_required
@customer_required
def project_export_csv(project_id):
    import csv, io as _io
    pr = _cust_rp_q().filter(RemediationProject.id == project_id).first() or abort(404)
    latest = _latest_import()
    items = pr.items.order_by(desc(RemediationItem.cvss_score)).all()
    live = _live_plugin_counts(latest.id if latest else None,
                               [i.plugin_id for i in items if i.plugin_id])
    buf = _io.StringIO()
    w = csv.writer(buf)
    w.writerow(['Project', 'Status', 'Due Date', 'Solution', 'Plugin ID', 'Severity',
                'CVSS', 'Hosts (at scoping)', 'Findings (at scoping)',
                'Findings still present', 'Item Status', 'Assignee', 'Notes'])
    for i in items:
        w.writerow([pr.name, pr.display_status,
                    pr.due_date.isoformat() if pr.due_date else '',
                    i.plugin_name or '', i.plugin_id or '', i.risk_factor or '',
                    i.cvss_score if i.cvss_score is not None else '',
                    i.host_count or 0, i.finding_count or 0,
                    live.get(i.plugin_id, 0), i.status,
                    i.assignee.username if i.assignee else '', i.notes or ''])
    cust = get_current_customer()
    fname = f"Project-{(cust.name + '-') if cust else ''}{pr.name}".replace(' ', '_')
    from flask import Response
    return Response(buf.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename="{fname}.csv"'})


# ── Asset Inventory / Fingerprinting ─────────────────────────────────────────

CPE_RE = re.compile(r'(?:x-)?cpe:/([aoehf]):([^:\n\r]+?)(?::([^:\n\r]+?))?(?::([^:\n\r]+?))?(?:\s|$)')
OS_ID_RE = re.compile(r'Remote operating system\s*:\s*(.+)', re.IGNORECASE)


# Scanners do not agree on how to name software. Tenable emits CPE, while Cortex
# emits package URLs (pkg:rpm/redhat/kernel@5.14.0) and a shorter app:name@version
# form. All three have to land in the same inventory, so each is parsed into the
# same vendor/product shape rather than the inventory understanding only CPE.
PURL_RE = re.compile(r'^pkg:([a-z0-9.+-]+)/(.+?)(?:@([^?#]*))?(?:[?#].*)?$', re.I)
APP_RE  = re.compile(r'^app:([^@\s]+)(?:@(.*))?$', re.I)

# Distro namespaces read as the vendor of the package, which is what they are.
_PURL_VENDOR_SEGMENT = {
    'golang': -1,   # github.com/foo/bar -> foo is the meaningful owner
    'npm':     0,
    'maven':   0,   # io.netty -> the group is the vendor
}


def _parse_purl(purl):
    """pkg:type/namespace/name@version, namespace optional and possibly nested."""
    m = PURL_RE.match(purl.strip())
    if not m:
        return None
    ptype = m.group(1).lower()
    path  = [seg for seg in m.group(2).split('/') if seg]
    if not path:
        return None

    product = path[-1]
    ns      = path[:-1]
    if ns:
        # golang namespaces are host-prefixed (github.com/foo), so the host is
        # not the vendor; for the rest the first segment is.
        idx    = _PURL_VENDOR_SEGMENT.get(ptype, 0)
        vendor = ns[idx] if -len(ns) <= idx < len(ns) else ns[0]
        if ptype == 'golang' and len(ns) > 1 and '.' in ns[0]:
            vendor = ns[1]
        # Maven groups are reverse-DNS; the last segment is the recognisable
        # name, so io.netty reads as Netty rather than Io.Netty.
        if ptype == 'maven' and '.' in vendor:
            vendor = vendor.rsplit('.', 1)[-1]
    else:
        # No namespace, so there is no vendor. Using the package type would
        # label lodash as "Npm Lodash", which reads as a vendor it does not have.
        vendor = ''

    # Everything a purl describes is software installed on the host. The
    # operating system itself is identified separately, from plugin output.
    return {'type': 'a',
            'vendor': vendor.replace('_', ' ').strip(),
            'product': product.replace('_', ' ').strip(),
            'raw': purl.strip()}


def _parse_app(s):
    """Cortex's short form: app:sshd@8.7p1-48.el9_7, with no vendor."""
    m = APP_RE.match(s.strip())
    if not m:
        return None
    return {'type': 'a', 'vendor': '',
            'product': m.group(1).replace('_', ' ').strip(),
            'raw': s.strip()}


@lru_cache(maxsize=100_000)
def _parse_cpe(cpe_str):
    """
    Parse a software identifier into {type, vendor, product, raw}, or None.

    Cached because the inventory parses the same handful of thousands of
    distinct strings across hundreds of thousands of findings, several times
    per asset row.
    """
    cpe_str = (cpe_str or '').strip()
    if not cpe_str:
        return None
    if cpe_str.lower().startswith('pkg:'):
        return _parse_purl(cpe_str)
    if cpe_str.lower().startswith('app:'):
        return _parse_app(cpe_str)

    m = CPE_RE.match(cpe_str)
    if not m:
        return None
    vendor  = m.group(2).replace('_', ' ').strip()
    product = (m.group(3) or '').replace('_', ' ').replace('+', '+').strip()
    return {'type': m.group(1), 'vendor': vendor, 'product': product,
            'raw': cpe_str}


def _humanise(vendor, product):
    """Turn cpe vendor/product into a readable label."""
    VENDOR_MAP = {
        'microsoft': 'Microsoft', 'vmware': 'VMware', 'oracle': 'Oracle',
        'apache': 'Apache', 'haxx': 'curl', 'google': 'Google',
        'mozilla': 'Mozilla', 'intel': 'Intel', 'adobe': 'Adobe',
        'openssl': 'OpenSSL', '7-zip': '7-Zip', 'zohocorp': 'Zoho',
        'manageengine': 'ManageEngine', 'notepad-plus-plus': 'Notepad++',
        'azul': 'Azul', 'python': 'Python', 'wireshark': 'Wireshark',
        # Distro namespaces, which purl package identifiers carry as the vendor.
        'redhat': 'Red Hat', 'rocky': 'Rocky Linux', 'amzn': 'Amazon Linux',
        'ubuntu': 'Ubuntu', 'debian': 'Debian', 'alpine': 'Alpine',
        'centos': 'CentOS', 'suse': 'SUSE', 'opensuse': 'openSUSE',
    }
    v = VENDOR_MAP.get(vendor.lower(), vendor.title())
    p = product.title() if product else ''
    if not p:
        return v
    # Package ecosystems often repeat the vendor inside the product, giving
    # "Netty Netty-Handler" or "Core Jackson-Core". Short vendors are left
    # alone, since a two-letter match is a coincidence rather than a repeat.
    if len(vendor) >= 4 and vendor.lower() in product.lower():
        return p
    return f'{v} {p}'.strip()


def _inv_qs(import_id, search, os_filter, app_filter, has_filter):
    """Current inventory filters as a query-string prefix for the pager links."""
    from urllib.parse import urlencode
    parts = {'import_id': import_id}
    for k, v in (('search', search), ('os', os_filter),
                 ('app', app_filter), ('has', has_filter)):
        if v:
            parts[k] = v
    return urlencode(parts) + '&'


@app.route('/inventory')
@login_required
@customer_required
def inventory():
    import_id  = request.args.get('import_id', type=int)
    cpe_filter = request.args.get('cpe_type', '')   # 'a' / 'o' / 'h' / ''
    search     = request.args.get('search', '').strip()
    # The fingerprint table used to render every asset and filter them in the
    # browser. That does not scale, so the filters are now server-side and the
    # table is paged; the counts stay truthful across the whole estate rather
    # than describing only the page on screen.
    os_filter  = request.args.get('os', '').strip()
    app_filter = request.args.get('app', '').strip()
    has_filter = request.args.get('has', '').strip()     # 'os' | 'apps' | ''
    page       = request.args.get('page', 1, type=int)

    latest = _latest_import()
    if not latest:
        return render_template('inventory.html', no_data=True)

    current_import = (db.session.get(ScanImport, import_id) if import_id else latest) or latest

    # ── OS detection via "OS Identification" plugin ───────────────────────────
    os_plugin_rows = (Vulnerability.query
                      .filter_by(scan_import_id=current_import.id)
                      .filter(Vulnerability.plugin_name.like('%OS Identification%'),
                              Vulnerability.plugin_output.isnot(None))
                      .with_entities(Vulnerability.asset, Vulnerability.ip_address,
                                     Vulnerability.plugin_output)
                      .all())

    os_map = {}  # asset -> {'os': str, 'ip': str}
    for r in os_plugin_rows:
        if r.asset in os_map:
            continue
        m = OS_ID_RE.search(r.plugin_output or '')
        if m:
            os_map[r.asset] = {'os': m.group(1).strip(), 'ip': r.ip_address or ''}

    # ── CPE inventory ─────────────────────────────────────────────────────────
    cpe_q = (db.session.query(Vulnerability.asset, Vulnerability.ip_address,
                               Vulnerability.cpe)
             .filter(Vulnerability.scan_import_id == current_import.id,
                     Vulnerability.cpe.isnot(None),
                     Vulnerability.cpe != '')
             # One row per asset/identifier pair. A finding-level read returns
             # the same pair once per CVE, which for a Cortex tenant is a couple
             # of hundred thousand rows to say the same few thousand things.
             .distinct().all())

    # asset -> set of unique CPE raw strings
    asset_cpes     = {}   # asset -> set of raw CPE strings
    app_inv        = {}   # label -> {vendor, product, hosts:set, raw_cpe}
    os_inv         = {}   # label -> {vendor, product, hosts:set}
    hw_inv         = {}   # label -> {vendor, product, hosts:set}
    asset_ip_map   = {}   # asset -> ip

    for r in cpe_q:
        parsed = _parse_cpe(r.cpe)
        if not parsed:
            continue
        asset_ip_map[r.asset] = r.ip_address or ''
        label = _humanise(parsed['vendor'], parsed['product'])
        if not label:
            continue

        asset_cpes.setdefault(r.asset, set()).add(r.cpe.strip())

        target = None
        if parsed['type'] == 'a':
            target = app_inv
        elif parsed['type'] == 'o':
            target = os_inv
        elif parsed['type'] in ('h', 'e'):
            target = hw_inv

        if target is not None:
            if label not in target:
                target[label] = {'label': label, 'vendor': parsed['vendor'],
                                 'product': parsed['product'],
                                 'raw': parsed['raw'], 'hosts': set()}
            target[label]['hosts'].add(r.asset)

    # Serialise
    def _finalise(inv):
        out = []
        for k, v in inv.items():
            out.append({'label': k, 'vendor': v['vendor'], 'product': v['product'],
                        'raw': v['raw'], 'host_count': len(v['hosts'])})
        return sorted(out, key=lambda x: -x['host_count'])

    top_apps = _finalise(app_inv)
    top_os   = _finalise(os_inv)
    top_hw   = _finalise(hw_inv)

    # ── OS distribution from parsed plugin output ─────────────────────────────
    os_dist = {}
    for info in os_map.values():
        os_dist[info['os']] = os_dist.get(info['os'], 0) + 1
    os_dist = dict(sorted(os_dist.items(), key=lambda x: -x[1]))

    # ── Per-asset fingerprint table ───────────────────────────────────────────
    # All unique assets in this scan
    all_assets_q = (db.session.query(
                        Vulnerability.asset,
                        Vulnerability.ip_address,
                        func.count(Vulnerability.id).label('vuln_count'),
                        _sev_count('Critical').label('critical'),
                        _sev_count('High').label('high'),
                        _sev_count('Medium').label('medium'),
                    )
                    .filter_by(scan_import_id=current_import.id, suppressed=False)
                    .group_by(Vulnerability.asset)
                    .order_by(Vulnerability.asset)
                    .all())

    asset_rows = []
    for a in all_assets_q:
        cpes = asset_cpes.get(a.asset, set())
        # Parse each identifier once per asset rather than four times.
        parsed_cpes = [p for p in (_parse_cpe(c) for c in cpes) if p]
        app_labels  = {_humanise(p['vendor'], p['product'])
                       for p in parsed_cpes
                       if p['type'] == 'a' and p['product']}
        apps        = sorted(app_labels)[:8]
        os_info = os_map.get(a.asset, {})
        asset_rows.append({
            'asset': a.asset,
            'ip': a.ip_address or '',
            'os': os_info.get('os', ''),
            'apps': apps,
            'app_count': sum(1 for p in parsed_cpes if p['type'] == 'a'),
            'vuln_count': a.vuln_count,
            'critical': a.critical or 0,
            'high': a.high or 0,
            'medium': a.medium or 0,
        })

    # Apply filters. OS and application both come from parsed CPE and plugin
    # output rather than from a column, so they cannot be pushed into SQL.
    if search:
        sl = search.lower()
        asset_rows = [r for r in asset_rows
                      if sl in r['asset'].lower()
                      or sl in r['ip'].lower()
                      or sl in r['os'].lower()
                      or any(sl in a.lower() for a in r['apps'])]
    if os_filter:
        ol = os_filter.lower()
        asset_rows = [r for r in asset_rows if ol in r['os'].lower()]
    if app_filter:
        al = app_filter.lower()
        asset_rows = [r for r in asset_rows
                      if any(al in a.lower() for a in r['apps'])]
    if has_filter == 'os':
        asset_rows = [r for r in asset_rows if r['os']]
    elif has_filter == 'apps':
        asset_rows = [r for r in asset_rows if r['apps']]

    asset_total = len(asset_rows)
    per_page    = 100
    asset_pages = max(1, -(-asset_total // per_page))
    page        = max(1, min(page, asset_pages))
    asset_rows  = asset_rows[(page - 1) * per_page:page * per_page]

    # ── Changes vs previous import ────────────────────────────────────────────
    prev = (_cust_scan_q()
            .filter(ScanImport.imported_at < current_import.imported_at)
            .order_by(desc(ScanImport.imported_at)).first())

    new_software, removed_software, os_changes = [], [], []
    if prev:
        prev_app_set = set(
            r.cpe for r in
            db.session.query(Vulnerability.cpe)
            .filter(Vulnerability.scan_import_id == prev.id,
                    Vulnerability.cpe.like('cpe:/a:%')).distinct().all()
            if r.cpe
        )
        cur_app_set = set(
            r.cpe for r in
            db.session.query(Vulnerability.cpe)
            .filter(Vulnerability.scan_import_id == current_import.id,
                    Vulnerability.cpe.like('cpe:/a:%')).distinct().all()
            if r.cpe
        )
        for cpe_str in sorted(cur_app_set - prev_app_set):
            p = _parse_cpe(cpe_str)
            if p:
                new_software.append(_humanise(p['vendor'], p['product']))
        for cpe_str in sorted(prev_app_set - cur_app_set):
            p = _parse_cpe(cpe_str)
            if p:
                removed_software.append(_humanise(p['vendor'], p['product']))

        # OS changes per host
        prev_os_rows = (Vulnerability.query
                        .filter_by(scan_import_id=prev.id)
                        .filter(Vulnerability.plugin_name.like('%OS Identification%'),
                                Vulnerability.plugin_output.isnot(None))
                        .with_entities(Vulnerability.asset, Vulnerability.plugin_output)
                        .all())
        prev_os_map = {}
        for r in prev_os_rows:
            m = OS_ID_RE.search(r.plugin_output or '')
            if m:
                prev_os_map[r.asset] = m.group(1).strip()
        for asset, info in os_map.items():
            if asset in prev_os_map and prev_os_map[asset] != info['os']:
                os_changes.append({'asset': asset, 'before': prev_os_map[asset],
                                   'after': info['os']})

    # ── KPIs ─────────────────────────────────────────────────────────────────
    total_assets    = len(all_assets_q)
    os_identified   = len(os_map)
    unique_apps     = len(app_inv)
    unique_os_types = len(os_dist)

    all_imports = _cust_scan_q().order_by(desc(ScanImport.imported_at)).all()

    return render_template('inventory.html',
        no_data=False, latest=current_import, all_imports=all_imports,
        current_import_id=current_import.id,
        total_assets=total_assets, os_identified=os_identified,
        unique_apps=unique_apps, unique_os_types=unique_os_types,
        os_dist=os_dist,
        top_apps=top_apps[:25],
        top_os=top_os[:15],
        top_hw=top_hw[:10],
        asset_rows=asset_rows,
        asset_total=asset_total, asset_page=page, asset_pages=asset_pages,
        os_filter=os_filter, app_filter=app_filter, has_filter=has_filter,
        inv_qs=_inv_qs(current_import.id, search, os_filter, app_filter, has_filter),
        new_software=new_software[:30],
        removed_software=removed_software[:30],
        os_changes=os_changes,
        has_prev=bool(prev),
        search=search,
        os_dist_json=json.dumps(dict(list(os_dist.items())[:10])),
        top_apps_json=json.dumps([(a['label'], a['host_count']) for a in top_apps[:15]]),
    )


# ── CVE Analysis ──────────────────────────────────────────────────────────────

CVE_RE = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)


@app.route('/cves')
@login_required
@customer_required
def cve_list():
    import_id      = request.args.get('import_id', type=int)
    sev_filter     = request.args.get('severity', '')
    year_filter    = request.args.get('year', '', type=str)
    search         = request.args.get('search', '').strip()

    latest = _latest_import()
    if not latest:
        return render_template('cves.html', no_data=True)

    current_import = (db.session.get(ScanImport, import_id) if import_id else latest) or latest

    # ── Aggregate CVE findings (vulnerability_id LIKE 'CVE-%') ───────────────
    q = (db.session.query(
            Vulnerability.vulnerability_id.label('cve_id'),
            Vulnerability.risk_factor,
            Vulnerability.synopsis,
            func.count(func.distinct(Vulnerability.asset)).label('host_count'),
            func.count(Vulnerability.id).label('instance_count'),
            func.max(Vulnerability.cvss_v3_score).label('cvss3'),
            func.max(Vulnerability.cvss_v4_score).label('cvss4'),
            func.min(Vulnerability.first_seen).label('first_seen'),
            func.max(Vulnerability.last_seen).label('last_seen'),
         )
         .filter(
             Vulnerability.scan_import_id == current_import.id,
             Vulnerability.vulnerability_id.like('CVE-%'),
             Vulnerability.suppressed == False,
         ))

    if sev_filter:
        q = q.filter(Vulnerability.risk_factor == sev_filter)
    if year_filter:
        q = q.filter(Vulnerability.vulnerability_id.like(f'CVE-{year_filter}-%'))
    if search:
        q = q.filter(or_(
            Vulnerability.vulnerability_id.ilike(f'%{search}%'),
            Vulnerability.synopsis.ilike(f'%{search}%'),
        ))

    cve_rows_all = (q.group_by(Vulnerability.vulnerability_id)
                     .order_by(desc(func.max(Vulnerability.cvss_v3_score)),
                               desc(func.count(func.distinct(Vulnerability.asset))))
                     .all())
    # Cap rendered rows. MCR's 22,551 CVEs produced a 40 MB page. KPIs and charts
    # below are computed from the full set, only the table is limited.
    CVE_ROW_LIMITS = (100, 250, 500, 1000)
    cve_row_limit = request.args.get('limit', type=int)
    if cve_row_limit not in CVE_ROW_LIMITS and cve_row_limit != 0:
        cve_row_limit = 250
    cve_rows = cve_rows_all

    # ── KPIs ─────────────────────────────────────────────────────────────────
    total_cves       = len(cve_rows)
    critical_high    = sum(1 for r in cve_rows if r.risk_factor in ('Critical', 'High'))
    with_cvss        = sum(1 for r in cve_rows if r.cvss3)
    cvss_scores      = [r.cvss3 for r in cve_rows if r.cvss3]
    avg_cvss         = round(sum(cvss_scores) / len(cvss_scores), 1) if cvss_scores else 0
    affected_assets  = len({a for r in cve_rows for a in []})  # computed below
    total_instances  = sum(r.instance_count for r in cve_rows)

    # Distinct affected assets for this import's CVE findings
    asset_q = (db.session.query(func.count(func.distinct(Vulnerability.asset)))
               .filter(
                   Vulnerability.scan_import_id == current_import.id,
                   Vulnerability.vulnerability_id.like('CVE-%'),
                   Vulnerability.suppressed == False,
               ).scalar() or 0)
    affected_assets = asset_q

    # ── Charts data ───────────────────────────────────────────────────────────
    # Severity distribution
    sev_dist = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
    for r in cve_rows:
        if r.risk_factor in sev_dist:
            sev_dist[r.risk_factor] += 1

    # CVE year distribution
    year_dist = {}
    for r in cve_rows:
        m = re.match(r'CVE-(\d{4})-', r.cve_id)
        if m:
            y = m.group(1)
            year_dist[y] = year_dist.get(y, 0) + 1
    year_dist = dict(sorted(year_dist.items()))

    # Top 15 by host count
    top15 = [(r.cve_id, r.host_count, r.cvss3 or 0, r.risk_factor)
             for r in sorted(cve_rows, key=lambda x: x.host_count, reverse=True)[:15]]

    # CVSS buckets
    cvss_buckets = {'0–3.9': 0, '4–6.9': 0, '7–8.9': 0, '9–10': 0}
    for s in cvss_scores:
        if s < 4:    cvss_buckets['0–3.9'] += 1
        elif s < 7:  cvss_buckets['4–6.9'] += 1
        elif s < 9:  cvss_buckets['7–8.9'] += 1
        else:        cvss_buckets['9–10']  += 1

    # Available years for filter dropdown
    all_years = sorted(year_dist.keys(), reverse=True)

    all_imports = _cust_scan_q().order_by(desc(ScanImport.imported_at)).all()

    return render_template('cves.html',
        no_data=False, latest=current_import, all_imports=all_imports,
        current_import_id=current_import.id,
        cve_rows=(cve_rows_all if cve_row_limit == 0 else cve_rows_all[:cve_row_limit]),
        total_rows=len(cve_rows_all), row_limit=cve_row_limit, row_limits=CVE_ROW_LIMITS,
        total_cves=total_cves, critical_high=critical_high, with_cvss=with_cvss,
        avg_cvss=avg_cvss, affected_assets=affected_assets, total_instances=total_instances,
        sev_dist_json=json.dumps(sev_dist),
        year_dist_json=json.dumps(year_dist),
        top15_json=json.dumps(top15),
        cvss_buckets_json=json.dumps(cvss_buckets),
        all_years=all_years,
        sev_filter=sev_filter, year_filter=year_filter, search=search,
    )


@app.route('/cves/<cve_id>')
@login_required
@customer_required
def cve_detail(cve_id):
    import_id = request.args.get('import_id', type=int)
    latest    = _latest_import()
    if not latest:
        abort(404)
    current_import = (db.session.get(ScanImport, import_id) if import_id else latest) or latest

    # Direct CVE findings
    direct = (Vulnerability.query
              .filter_by(scan_import_id=current_import.id, vulnerability_id=cve_id)
              .filter(Vulnerability.suppressed == False)
              .all())

    if not direct:
        abort(404)

    sample    = direct[0]
    host_list = sorted({v.asset for v in direct})
    host_rows = (db.session.query(
                    Vulnerability.asset,
                    Vulnerability.ip_address,
                    func.count(Vulnerability.id).label('instances'),
                    func.min(Vulnerability.first_seen).label('first_seen'),
                    func.max(Vulnerability.last_seen).label('last_seen'),
                 )
                 .filter_by(scan_import_id=current_import.id, vulnerability_id=cve_id)
                 .group_by(Vulnerability.asset)
                 .order_by(desc('instances'))
                 .all())

    # TENABLE-NOCVE entries that mention this CVE in their text
    related = (Vulnerability.query
               .filter(
                   Vulnerability.scan_import_id == current_import.id,
                   ~Vulnerability.vulnerability_id.like('CVE-%'),
                   or_(
                       Vulnerability.description.contains(cve_id),
                       Vulnerability.plugin_output.contains(cve_id),
                       Vulnerability.synopsis.contains(cve_id),
                   ),
                   Vulnerability.suppressed == False,
               ).all())

    # Trend across all imports
    all_imports_q = _cust_scan_q().order_by(ScanImport.imported_at).all()
    history = []
    for imp in all_imports_q:
        cnt = Vulnerability.query.filter_by(
            scan_import_id=imp.id, vulnerability_id=cve_id, suppressed=False).count()
        label = imp.report_date.isoformat() if imp.report_date else imp.imported_at.strftime('%Y-%m-%d')
        history.append({'date': label, 'count': cnt, 'import_id': imp.id})

    cvss3 = max((v.cvss_v3_score for v in direct if v.cvss_v3_score), default=None)
    cvss4 = max((v.cvss_v4_score for v in direct if v.cvss_v4_score), default=None)

    # Extract year from CVE ID
    m = re.match(r'CVE-(\d{4})-(\d+)', cve_id)
    cve_year   = m.group(1) if m else '—'
    cve_number = m.group(2) if m else cve_id

    all_imports = _cust_scan_q().order_by(desc(ScanImport.imported_at)).all()

    return render_template('cve_detail.html',
        cve_id=cve_id, cve_year=cve_year, cve_number=cve_number,
        sample=sample, cvss3=cvss3, cvss4=cvss4,
        host_rows=host_rows, host_count=len(host_rows),
        instance_count=len(direct),
        related=related,
        history_json=json.dumps(history),
        latest=current_import, all_imports=all_imports,
        current_import_id=current_import.id,
    )


# ── Plugins ───────────────────────────────────────────────────────────────────

@app.route('/plugins')
@login_required
@customer_required
def plugins():
    import_id = request.args.get('import_id', type=int)
    severity   = request.args.get('severity', '')
    family     = request.args.get('family', '')
    has_cvss   = request.args.get('has_cvss', '')
    search     = request.args.get('search', '').strip()

    latest = _latest_import()
    if not import_id and latest:
        import_id = latest.id

    all_imports = _cust_scan_q().order_by(desc(ScanImport.imported_at)).all()

    q = db.session.query(
        Vulnerability.plugin_id,
        Vulnerability.plugin_name,
        Vulnerability.plugin_family,
        Vulnerability.risk_factor,
        func.max(Vulnerability.cvss_v3_score).label('cvss3'),
        func.max(Vulnerability.cvss_v4_score).label('cvss4'),
        func.count(Vulnerability.asset.distinct()).label('host_count'),
        func.count(Vulnerability.id).label('finding_count'),
        func.min(Vulnerability.first_seen).label('first_seen'),
        func.max(Vulnerability.last_seen).label('last_seen'),
    ).filter_by(scan_import_id=import_id).group_by(Vulnerability.plugin_id)

    if severity:
        q = q.filter(Vulnerability.risk_factor == severity)
    if family:
        q = q.filter(Vulnerability.plugin_family == family)
    if has_cvss == '1':
        q = q.having(func.max(Vulnerability.cvss_v3_score) > 0)
    if search:
        q = q.filter(or_(
            Vulnerability.plugin_name.ilike(f'%{search}%'),
            Vulnerability.plugin_id.ilike(f'%{search}%'),
            Vulnerability.plugin_family.ilike(f'%{search}%'),
        ))

    # Cap rendered rows. MCR has 22,566 plugins; sending them all produced a
    # 33 MB page the browser could not cope with, the same failure Remediation
    # had. Aggregates below still use the full set.
    PLUGIN_ROW_LIMITS = (100, 250, 500, 1000)
    plugin_row_limit = request.args.get('limit', type=int)
    if plugin_row_limit not in PLUGIN_ROW_LIMITS and plugin_row_limit != 0:
        plugin_row_limit = 250
    plugin_rows_all = q.order_by(desc('host_count')).all()
    plugin_rows = (plugin_rows_all if plugin_row_limit == 0
                   else plugin_rows_all[:plugin_row_limit])

    # --- KPIs (always unfiltered) ---
    all_plugins = db.session.query(
        Vulnerability.plugin_id,
        Vulnerability.plugin_family,
        Vulnerability.risk_factor,
        func.max(Vulnerability.cvss_v3_score).label('cvss3'),
        func.count(Vulnerability.asset.distinct()).label('hosts'),
    ).filter_by(scan_import_id=import_id).group_by(Vulnerability.plugin_id).all()

    total_plugins  = len(all_plugins)
    critical_high  = sum(1 for p in all_plugins if p.risk_factor in ('Critical','High'))
    medium_count   = sum(1 for p in all_plugins if p.risk_factor == 'Medium')
    with_cvss      = sum(1 for p in all_plugins if p.cvss3)
    families_count = len(set(r.plugin_family for r in plugin_rows))

    # --- Chart data ---
    sev_dist = {}
    for p in all_plugins:
        sev_dist[p.risk_factor] = sev_dist.get(p.risk_factor, 0) + 1

    # Families distribution (unique plugins per family, top 12)
    fam_dist = {}
    for p in all_plugins:
        fam_dist[p.plugin_family or 'Unknown'] = fam_dist.get(p.plugin_family or 'Unknown', 0) + 1
    fam_dist = sorted(fam_dist.items(), key=lambda x: -x[1])[:12]

    # Top 15 by host count for bar chart
    top15 = [(r.plugin_name, r.plugin_id, int(r.host_count)) for r in plugin_rows[:15]]

    # CVSS score distribution (buckets)
    cvss_buckets = {'0–3.9': 0, '4–6.9': 0, '7–8.9': 0, '9–10': 0}
    for p in all_plugins:
        if p.cvss3:
            s = float(p.cvss3)
            if s < 4:    cvss_buckets['0–3.9'] += 1
            elif s < 7:  cvss_buckets['4–6.9'] += 1
            elif s < 9:  cvss_buckets['7–8.9'] += 1
            else:        cvss_buckets['9–10']   += 1

    # Families for filter dropdown
    families_list = sorted(set(r.plugin_family for r in
                               db.session.query(Vulnerability.plugin_family)
                               .filter_by(scan_import_id=import_id)
                               .distinct().all() if r.plugin_family))

    return render_template('plugins.html',
                           plugin_rows=plugin_rows,
                           total_rows=len(plugin_rows_all),
                           row_limit=plugin_row_limit, row_limits=PLUGIN_ROW_LIMITS,
                           total_plugins=total_plugins,
                           critical_high=critical_high,
                           medium_count=medium_count,
                           with_cvss=with_cvss,
                           families_count=families_count,
                           all_imports=all_imports,
                           current_import_id=import_id,
                           severity=severity,
                           family=family,
                           has_cvss=has_cvss,
                           search=search,
                           families_list=families_list,
                           sev_dist_json=json.dumps(sev_dist),
                           fam_dist_json=json.dumps(fam_dist),
                           top15_json=json.dumps(top15),
                           cvss_buckets_json=json.dumps(cvss_buckets))


@app.route('/plugins/<plugin_id>')
@login_required
@customer_required
def plugin_detail(plugin_id):
    import_id = request.args.get('import_id', type=int)
    latest = _latest_import()
    if not import_id and latest:
        import_id = latest.id

    all_imports = _cust_scan_q().order_by(desc(ScanImport.imported_at)).all()

    # Full sample record (for description, synopsis, solution, etc.)
    sample = (Vulnerability.query
              .filter_by(plugin_id=plugin_id, scan_import_id=import_id)
              .order_by(desc(Vulnerability.severity_level)).first())
    if not sample:
        abort(404)

    # Aggregate stats for this plugin in this import
    stats = db.session.query(
        func.count(Vulnerability.asset.distinct()).label('host_count'),
        func.count(Vulnerability.id).label('finding_count'),
        func.max(Vulnerability.cvss_v3_score).label('cvss3'),
        func.max(Vulnerability.cvss_v4_score).label('cvss4'),
        func.min(Vulnerability.first_seen).label('first_seen'),
        func.max(Vulnerability.last_seen).label('last_seen'),
    ).filter_by(plugin_id=plugin_id, scan_import_id=import_id).first()

    # Affected hosts
    host_rows = (db.session.query(
        Vulnerability.asset,
        Vulnerability.ip_address,
        func.count(Vulnerability.id).label('findings'),
        func.min(Vulnerability.first_seen).label('first_seen'),
        func.max(Vulnerability.last_seen).label('last_seen'),
        func.group_concat(Vulnerability.port.distinct()).label('ports'),
    ).filter_by(plugin_id=plugin_id, scan_import_id=import_id)
     .group_by(Vulnerability.asset)
     .order_by(Vulnerability.asset).all())

    # Ports this plugin fires on
    port_rows = (db.session.query(
        Vulnerability.port,
        Vulnerability.protocol,
        func.count(Vulnerability.asset.distinct()).label('host_count'),
    ).filter(Vulnerability.plugin_id == plugin_id,
             Vulnerability.scan_import_id == import_id,
             Vulnerability.port != '0',
             Vulnerability.port != '',
             Vulnerability.port.isnot(None))
     .group_by(Vulnerability.port, Vulnerability.protocol)
     .order_by(desc('host_count')).all())

    # Similar plugins (same family, excluding self)
    similar = (db.session.query(
        Vulnerability.plugin_id,
        Vulnerability.plugin_name,
        Vulnerability.risk_factor,
        func.count(Vulnerability.asset.distinct()).label('hosts'),
    ).filter_by(plugin_family=sample.plugin_family, scan_import_id=import_id)
     .filter(Vulnerability.plugin_id != plugin_id)
     .group_by(Vulnerability.plugin_id)
     .order_by(desc('hosts')).limit(10).all())

    # Week-over-week trend for this plugin
    hist = (db.session.query(
        ScanImport.imported_at,
        ScanImport.report_date,
        func.count(Vulnerability.asset.distinct()).label('hosts'),
        func.count(Vulnerability.id).label('findings'),
    ).join(Vulnerability)
     .filter(Vulnerability.plugin_id == plugin_id)
     .group_by(ScanImport.id)
     .order_by(ScanImport.imported_at).all())

    history_data = [{
        'date': (h.report_date.isoformat() if h.report_date else h.imported_at.strftime('%Y-%m-%d')),
        'hosts': h.hosts,
        'findings': h.findings,
    } for h in hist]

    return render_template('plugin_detail.html',
                           sample=sample,
                           stats=stats,
                           host_rows=host_rows,
                           port_rows=port_rows,
                           similar=similar,
                           history_data=json.dumps(history_data),
                           all_imports=all_imports,
                           current_import_id=import_id,
                           well_known=WELL_KNOWN_PORTS)


# ── Ports ─────────────────────────────────────────────────────────────────────

WELL_KNOWN_PORTS = {
    '21': 'FTP', '22': 'SSH', '23': 'Telnet', '25': 'SMTP', '53': 'DNS',
    '67': 'DHCP', '69': 'TFTP', '80': 'HTTP', '88': 'Kerberos', '110': 'POP3',
    '111': 'RPC', '123': 'NTP', '135': 'MS-RPC', '137': 'NetBIOS-NS',
    '138': 'NetBIOS-DGM', '139': 'NetBIOS-SSN', '143': 'IMAP', '161': 'SNMP',
    '389': 'LDAP', '443': 'HTTPS', '445': 'SMB', '465': 'SMTPS',
    '500': 'IKE/IPSec', '514': 'Syslog', '587': 'SMTP-Submission',
    '636': 'LDAPS', '993': 'IMAPS', '995': 'POP3S', '1433': 'MSSQL',
    '1521': 'Oracle DB', '2701': 'SMS-RPC', '3268': 'LDAP-GC', '3269': 'LDAPS-GC',
    '3306': 'MySQL', '3389': 'RDP', '4500': 'IPSec-NAT-T', '5432': 'PostgreSQL',
    '5985': 'WinRM-HTTP', '5986': 'WinRM-HTTPS', '6379': 'Redis',
    '8080': 'HTTP-Alt', '8443': 'HTTPS-Alt', '8888': 'HTTP-Alt',
    '47001': 'WinRM', '49664': 'MS-Ephemeral', '49665': 'MS-Ephemeral',
}


@app.route('/ports')
@login_required
@customer_required
def ports():
    import_id = request.args.get('import_id', type=int)
    search = request.args.get('search', '').strip()
    proto_filter = request.args.get('proto', '')

    latest = _latest_import()
    if not import_id and latest:
        import_id = latest.id

    all_imports = _cust_scan_q().order_by(desc(ScanImport.imported_at)).all()

    base = [
        Vulnerability.scan_import_id == import_id,
        Vulnerability.port != '0',
        Vulnerability.port != '',
        Vulnerability.port.isnot(None),
    ]
    if proto_filter:
        base.append(Vulnerability.protocol == proto_filter)
    if search:
        base.append(or_(
            Vulnerability.port.ilike(f'%{search}%'),
            Vulnerability.asset.ilike(f'%{search}%'),
            Vulnerability.ip_address.ilike(f'%{search}%'),
        ))

    # Per-port summary
    port_rows = (db.session.query(
        Vulnerability.port,
        Vulnerability.protocol,
        func.count(Vulnerability.asset.distinct()).label('host_count'),
        func.count(Vulnerability.id).label('finding_count'),
    ).filter(*base)
     .group_by(Vulnerability.port, Vulnerability.protocol)
     .order_by(desc('host_count'), Vulnerability.port)
     .all())

    # Per-host summary (port count + comma-separated port list)
    host_rows = (db.session.query(
        Vulnerability.asset,
        Vulnerability.ip_address,
        func.count(Vulnerability.port.distinct()).label('port_count'),
        func.group_concat(Vulnerability.port.distinct()).label('port_list'),
    ).filter(*base)
     .group_by(Vulnerability.asset)
     .order_by(desc('port_count'))
     .all())

    # Summary KPIs (unfiltered by search/proto for accuracy)
    base_kpi = [
        Vulnerability.scan_import_id == import_id,
        Vulnerability.port != '0',
        Vulnerability.port != '',
        Vulnerability.port.isnot(None),
    ]
    total_ports    = db.session.query(func.count(Vulnerability.port.distinct())).filter(*base_kpi).scalar() or 0
    tcp_ports      = db.session.query(func.count(Vulnerability.port.distinct())).filter(*base_kpi, Vulnerability.protocol == 'tcp').scalar() or 0
    udp_ports      = db.session.query(func.count(Vulnerability.port.distinct())).filter(*base_kpi, Vulnerability.protocol == 'udp').scalar() or 0
    hosts_count    = db.session.query(func.count(Vulnerability.asset.distinct())).filter(*base_kpi).scalar() or 0
    total_findings = db.session.query(func.count(Vulnerability.id)).filter(*base_kpi).scalar() or 0

    # Chart data: top 25 ports by host count
    top_for_chart = [(f"{r[0]}/{r[1]}", int(r[2])) for r in port_rows[:25]]

    # Protocol distribution for pie chart
    proto_dist = (db.session.query(Vulnerability.protocol, func.count(Vulnerability.port.distinct()))
                  .filter(*base_kpi)
                  .group_by(Vulnerability.protocol).all())

    return render_template('ports.html',
                           port_rows=port_rows,
                           host_rows=host_rows,
                           total_ports=total_ports,
                           tcp_ports=tcp_ports,
                           udp_ports=udp_ports,
                           hosts_count=hosts_count,
                           total_findings=total_findings,
                           all_imports=all_imports,
                           current_import_id=import_id,
                           search=search,
                           proto_filter=proto_filter,
                           well_known=WELL_KNOWN_PORTS,
                           top_chart_json=json.dumps(top_for_chart),
                           proto_dist_json=json.dumps([(p or 'other', c) for p, c in proto_dist]))


@app.route('/ports/<port>/<proto>')
@login_required
@customer_required
def port_detail(port, proto):
    import_id = request.args.get('import_id', type=int)
    latest = _latest_import()
    if not import_id and latest:
        import_id = latest.id

    all_imports = _cust_scan_q().order_by(desc(ScanImport.imported_at)).all()

    base = [
        Vulnerability.scan_import_id == import_id,
        Vulnerability.port == port,
        Vulnerability.protocol == proto,
    ]

    # All hosts with this port open
    host_rows = (db.session.query(
        Vulnerability.asset,
        Vulnerability.ip_address,
        func.count(Vulnerability.id).label('finding_count'),
        func.min(Vulnerability.first_seen).label('first_seen'),
        func.max(Vulnerability.last_seen).label('last_seen'),
    ).filter(*base)
     .group_by(Vulnerability.asset)
     .order_by(Vulnerability.asset)
     .all())

    # All distinct services/plugins detected on this port
    plugin_rows = (db.session.query(
        Vulnerability.plugin_name,
        Vulnerability.risk_factor,
        func.count(Vulnerability.asset.distinct()).label('host_count'),
        func.count(Vulnerability.id).label('finding_count'),
    ).filter(*base)
     .group_by(Vulnerability.plugin_name)
     .order_by(desc('host_count'))
     .all())

    # Individual findings for this port (for the full table)
    findings = (Vulnerability.query
                .filter(*base)
                .order_by(desc(Vulnerability.severity_level), Vulnerability.asset)
                .all())

    # Severity breakdown for this port
    sev = {k: 0 for k in ('Critical', 'High', 'Medium', 'Low', 'Informational')}
    for v in findings:
        if v.risk_factor in sev:
            sev[v.risk_factor] += 1

    service_name = WELL_KNOWN_PORTS.get(port, '')

    return render_template('port_detail.html',
                           port=port,
                           proto=proto,
                           service_name=service_name,
                           host_rows=host_rows,
                           plugin_rows=plugin_rows,
                           findings=findings,
                           sev=sev,
                           all_imports=all_imports,
                           current_import_id=import_id)


# ── Search ────────────────────────────────────────────────────────────────────

@app.route('/search')
@login_required
@customer_required
def search():
    q = request.args.get('q', '').strip()
    scope = request.args.get('scope', 'latest')
    results = []
    total = 0

    if q and len(q) >= 2:
        base = Vulnerability.query
        if scope == 'latest':
            latest = _latest_import()
            if latest:
                base = base.filter_by(scan_import_id=latest.id)

        base = base.filter(or_(
            Vulnerability.plugin_name.ilike(f'%{q}%'),
            Vulnerability.asset.ilike(f'%{q}%'),
            Vulnerability.ip_address.ilike(f'%{q}%'),
            Vulnerability.synopsis.ilike(f'%{q}%'),
            Vulnerability.vulnerability_id.ilike(f'%{q}%'),
            Vulnerability.cpe.ilike(f'%{q}%'),
            Vulnerability.solution.ilike(f'%{q}%'),
            Vulnerability.plugin_family.ilike(f'%{q}%'),
        ))
        total = base.count()
        results = base.order_by(desc(Vulnerability.severity_level)).limit(300).all()

    return render_template('search.html', q=q, results=results, total=total, scope=scope)


@app.route('/trends/family/<path:family_name>')
@login_required
@customer_required
def family_detail(family_name):
    import_id = request.args.get('import_id', type=int)
    latest = _latest_import()
    if not import_id and latest:
        import_id = latest.id

    all_imports = _cust_scan_q().order_by(desc(ScanImport.imported_at)).all()

    base = [Vulnerability.plugin_family == family_name,
            Vulnerability.scan_import_id == import_id]

    # Severity breakdown
    sev = {k: 0 for k in ('Critical', 'High', 'Medium', 'Low', 'Informational')}
    sev_rows = (db.session.query(Vulnerability.risk_factor, func.count(Vulnerability.id))
                .filter(*base).group_by(Vulnerability.risk_factor).all())
    for rf, cnt in sev_rows:
        if rf in sev:
            sev[rf] = cnt

    total = sum(sev.values())

    # Hosts affected
    host_rows = (db.session.query(
        Vulnerability.asset,
        Vulnerability.ip_address,
        func.count(Vulnerability.id).label('total'),
        _sev_count('Critical').label('critical'),
        _sev_count('High').label('high'),
        _sev_count('Medium').label('medium'),
        _risk_score_expr().label('risk_score'),
    ).filter(*base)
     .group_by(Vulnerability.asset)
     .order_by(desc('risk_score')).all())

    # Open ports seen in this family
    port_rows = (db.session.query(
        Vulnerability.port,
        Vulnerability.protocol,
        func.count(Vulnerability.asset.distinct()).label('host_count'),
        func.count(Vulnerability.id).label('finding_count'),
    ).filter(*base, Vulnerability.port != '0', Vulnerability.port != '',
             Vulnerability.port.isnot(None))
     .group_by(Vulnerability.port, Vulnerability.protocol)
     .order_by(desc('host_count')).all())

    # Top plugins in this family
    plugin_rows = (db.session.query(
        Vulnerability.plugin_name,
        Vulnerability.plugin_id,
        Vulnerability.risk_factor,
        func.count(Vulnerability.asset.distinct()).label('host_count'),
        func.count(Vulnerability.id).label('finding_count'),
    ).filter(*base)
     .group_by(Vulnerability.plugin_name)
     .order_by(desc('host_count')).all())

    # Week-over-week trend for this family
    hist = (db.session.query(
        ScanImport.imported_at,
        ScanImport.report_date,
        func.count(Vulnerability.id).label('total'),
        _sev_count('Critical').label('critical'),
        _sev_count('High').label('high'),
        _sev_count('Medium').label('medium'),
    ).join(Vulnerability)
     .filter(Vulnerability.plugin_family == family_name)
     .group_by(ScanImport.id)
     .order_by(ScanImport.imported_at).all())

    history_data = [{
        'date': (h.report_date.isoformat() if h.report_date else h.imported_at.strftime('%Y-%m-%d')),
        'total': h.total, 'critical': h.critical, 'high': h.high, 'medium': h.medium,
    } for h in hist]

    return render_template('family_detail.html',
                           family_name=family_name,
                           sev=sev,
                           total=total,
                           host_rows=host_rows,
                           port_rows=port_rows,
                           plugin_rows=plugin_rows,
                           history_data=json.dumps(history_data),
                           all_imports=all_imports,
                           current_import_id=import_id,
                           well_known=WELL_KNOWN_PORTS)


# ── Asset Groups ─────────────────────────────────────────────────────────────

@app.route('/asset-groups')
@login_required
@customer_required
def asset_groups_list():
    groups = _cust_ag_q().order_by(AssetGroup.name).all()
    # Annotate each group with member count
    for g in groups:
        g._member_count = g.members.count()
    return render_template('asset_groups.html', groups=groups)


@app.route('/asset-groups/create', methods=['POST'])
@login_required
@analyst_required
def asset_group_create():
    name        = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    color       = request.form.get('color', '#1f6feb').strip()
    if not name:
        flash('Group name is required.', 'danger')
        return redirect(url_for('asset_groups_list'))
    if _cust_ag_q().filter_by(name=name).first():
        flash(f'A group named "{name}" already exists.', 'warning')
        return redirect(url_for('asset_groups_list'))
    cust  = get_current_customer()
    group = AssetGroup(name=name, description=description or None,
                       color=color, created_by_id=current_user.id,
                       customer_id=cust.id if cust else None)
    db.session.add(group)
    db.session.commit()
    flash(f'Asset group "{name}" created.', 'success')
    return redirect(url_for('asset_group_detail', group_id=group.id))


@app.route('/asset-groups/<int:group_id>')
@login_required
@customer_required
def asset_group_detail(group_id):
    group   = db.session.get(AssetGroup, group_id) or abort(404)
    members = (AssetGroupMember.query
               .filter_by(group_id=group_id)
               .order_by(AssetGroupMember.asset_name).all())
    member_names = {m.asset_name for m in members}

    # All known assets from the latest import for the picker
    latest = _latest_import()
    all_asset_names = []
    if latest:
        rows = (db.session.query(Vulnerability.asset)
                .filter_by(scan_import_id=latest.id)
                .filter(Vulnerability.asset != '')
                .distinct().order_by(Vulnerability.asset).all())
        all_asset_names = [r[0] for r in rows]
    available = [a for a in all_asset_names if a not in member_names]

    return render_template('asset_group_detail.html',
                           group=group, members=members,
                           available=available, member_names=member_names)


@app.route('/asset-groups/<int:group_id>/update', methods=['POST'])
@login_required
@analyst_required
def asset_group_update(group_id):
    group = db.session.get(AssetGroup, group_id) or abort(404)
    new_name = request.form.get('name', '').strip()
    new_desc = request.form.get('description', '').strip()
    new_color = request.form.get('color', '#1f6feb').strip()
    if not new_name:
        flash('Group name cannot be empty.', 'danger')
        return redirect(url_for('asset_group_detail', group_id=group_id))
    existing = _cust_ag_q().filter_by(name=new_name).first()
    if existing and existing.id != group_id:
        flash(f'A group named "{new_name}" already exists.', 'warning')
        return redirect(url_for('asset_group_detail', group_id=group_id))
    group.name        = new_name
    group.description = new_desc or None
    group.color       = new_color
    db.session.commit()
    flash('Group updated.', 'success')
    return redirect(url_for('asset_group_detail', group_id=group_id))


@app.route('/asset-groups/<int:group_id>/add-assets', methods=['POST'])
@login_required
@analyst_required
def asset_group_add_assets(group_id):
    group    = db.session.get(AssetGroup, group_id) or abort(404)
    selected = request.form.getlist('asset_names')
    existing = {m.asset_name for m in AssetGroupMember.query.filter_by(group_id=group_id).all()}
    added = 0
    for name in selected:
        name = name.strip()
        if name and name not in existing:
            db.session.add(AssetGroupMember(group_id=group_id, asset_name=name))
            added += 1
    db.session.commit()
    flash(f'Added {added} asset(s) to "{group.name}".', 'success')
    return redirect(url_for('asset_group_detail', group_id=group_id))


@app.route('/asset-groups/<int:group_id>/remove-asset', methods=['POST'])
@login_required
@analyst_required
def asset_group_remove_asset(group_id):
    group      = db.session.get(AssetGroup, group_id) or abort(404)
    asset_name = request.form.get('asset_name', '').strip()
    member     = AssetGroupMember.query.filter_by(group_id=group_id, asset_name=asset_name).first()
    if member:
        db.session.delete(member)
        db.session.commit()
        flash(f'Removed "{asset_name}" from "{group.name}".', 'info')
    return redirect(url_for('asset_group_detail', group_id=group_id))


@app.route('/asset-groups/<int:group_id>/delete', methods=['POST'])
@login_required
@admin_required
def asset_group_delete(group_id):
    group = db.session.get(AssetGroup, group_id) or abort(404)
    name  = group.name
    db.session.delete(group)
    db.session.commit()
    flash(f'Asset group "{name}" deleted.', 'danger')
    return redirect(url_for('asset_groups_list'))


# ── Risk Acceptance ───────────────────────────────────────────────────────────

def _next_ra_tag():
    """Generate the next sequential RA-YYYY-NNN tag."""
    year = datetime.utcnow().year
    prefix = f'RA-{year}-'
    # Tags carry a global unique constraint, so the sequence must be global too.
    # Scoping this to the current customer made a second customer collide on
    # RA-YYYY-001. Max is computed numerically so the sequence survives past 999.
    rows = (db.session.query(RiskAcceptance.tag)
            .filter(RiskAcceptance.tag.like(f'{prefix}%'))
            .all())
    highest = 0
    for (tag,) in rows:
        try:
            highest = max(highest, int(tag.rsplit('-', 1)[-1]))
        except (ValueError, AttributeError):
            continue
    return f'{prefix}{highest + 1:03d}'


@app.route('/risk-acceptance')
@login_required
@customer_required
def risk_acceptance():
    entries = _cust_ra_q().order_by(desc(RiskAcceptance.accepted_at)).all()
    now = datetime.utcnow()

    total     = len(entries)
    active    = sum(1 for e in entries if e.status == 'Active')
    expiring  = sum(1 for e in entries if e.expiring_soon)
    expired   = sum(1 for e in entries if e.status == 'Expired')
    revoked   = sum(1 for e in entries if e.status == 'Revoked')

    # Distinct assets from latest import for the autocomplete list
    latest = _latest_import()
    assets = []
    if latest:
        rows = (db.session.query(Vulnerability.asset)
                .filter_by(scan_import_id=latest.id, suppressed=False)
                .filter(Vulnerability.asset != '')
                .distinct().order_by(Vulnerability.asset).all())
        assets = [r[0] for r in rows]

    groups = _cust_ag_q().order_by(AssetGroup.name).all()

    return render_template('risk_acceptance.html',
        entries=entries, total=total, active=active,
        expiring=expiring, expired=expired, revoked=revoked,
        assets=assets, groups=groups, now=now,
        prefill_asset=request.args.get('asset', ''),
        prefill_plugin_id=request.args.get('plugin_id', ''),
        prefill_plugin_name=request.args.get('plugin_name', ''),
        prefill_vuln_id=request.args.get('vuln_id', ''),
        prefill_risk_factor=request.args.get('risk_factor', ''),
        prefill_scope=request.args.get('scope', ''),
        prefill_group_id=request.args.get('group_id', ''),
        auto_open=request.args.get('add', '0') == '1',
        max_ra_days=MAX_RA_DAYS,
        ra_min_expiry=(now + timedelta(days=1)).strftime('%Y-%m-%d'),
        ra_max_expiry=(now + timedelta(days=MAX_RA_DAYS)).strftime('%Y-%m-%d'),
    )


@app.route('/risk-acceptance/add', methods=['POST'])
@login_required
def risk_acceptance_add():
    scope        = request.form.get('scope', 'finding')
    group_id_str = request.form.get('group_id', '').strip()
    group_id     = int(group_id_str) if group_id_str.isdigit() else None
    asset        = request.form.get('asset', '').strip()
    plugin_id    = request.form.get('plugin_id', '').strip()
    plugin_name  = request.form.get('plugin_name', '').strip()
    vuln_id      = request.form.get('vulnerability_id', '').strip()
    risk_factor  = request.form.get('risk_factor', '').strip()
    reason       = request.form.get('reason', '').strip()
    notes        = request.form.get('notes', '').strip()
    expires_str  = request.form.get('expires_at', '').strip()

    if not reason:
        flash('A reason is required for risk acceptance.', 'danger')
        return redirect(url_for('risk_acceptance'))

    if scope == 'group' and not group_id:
        flash('Please select an asset group.', 'danger')
        return redirect(url_for('risk_acceptance'))

    # NBL-IT-020 section 19.2: expiry is mandatory and capped at MAX_RA_DAYS.
    max_expiry = datetime.utcnow() + timedelta(days=MAX_RA_DAYS)
    if not expires_str:
        flash(f'An expiry date is required, and may not exceed {MAX_RA_DAYS} days '
              f'(on or before {max_expiry.strftime("%Y-%m-%d")}).', 'danger')
        return redirect(url_for('risk_acceptance'))
    try:
        expires_at = datetime.strptime(expires_str, '%Y-%m-%d')
    except ValueError:
        flash('Expiry date could not be read. Use the date picker and try again.', 'danger')
        return redirect(url_for('risk_acceptance'))
    if expires_at.date() <= datetime.utcnow().date():
        flash('Expiry date must be in the future.', 'danger')
        return redirect(url_for('risk_acceptance'))
    if expires_at.date() > max_expiry.date():
        flash(f'A risk acceptance may not exceed {MAX_RA_DAYS} days (NBL-IT-020 section 19.2). '
              f'The latest permitted expiry is {max_expiry.strftime("%Y-%m-%d")}. '
              f'Renew the acceptance nearer the time if it is still required.', 'danger')
        return redirect(url_for('risk_acceptance'))

    cust = get_current_customer()
    entry = RiskAcceptance(
        tag=_next_ra_tag(),
        customer_id=cust.id if cust else None,
        scope=scope,
        group_id=group_id if scope == 'group' else None,
        asset=asset or None,
        plugin_id=plugin_id or None,
        plugin_name=plugin_name or None,
        vulnerability_id=vuln_id or None,
        risk_factor=risk_factor or None,
        reason=reason,
        notes=notes or None,
        accepted_by_id=current_user.id,
        expires_at=expires_at,
    )
    db.session.add(entry)
    db.session.commit()
    flash(f'Risk acceptance <strong>{entry.tag}</strong> recorded.', 'success')
    return redirect(url_for('risk_acceptance'))


@app.route('/vulnerabilities/<int:vuln_id>/suppress', methods=['POST'])
@login_required
@customer_required
def vulnerability_suppress(vuln_id):
    """
    Record a false positive determination against a finding.

    NBL-IT-020 section 14 requires the basis for the determination to be recorded,
    the finding to be suppressed rather than deleted so the decision stays auditable,
    and the suppression to be re-reviewed at least every six months.
    """
    vuln = db.get_or_404(Vulnerability, vuln_id)
    reason = request.form.get('suppression_reason', '').strip()

    if not reason:
        flash('A reason is required when suppressing a finding (NBL-IT-020 section 14).', 'danger')
        return redirect(url_for('vulnerability_detail', vuln_id=vuln_id))

    # Second-analyst rule: Critical and High may not be suppressed by the importer alone.
    if vuln.risk_factor in ('Critical', 'High') and current_user.role not in ('admin', 'analyst'):
        flash('Critical and High findings require analyst or admin validation before suppression.', 'danger')
        return redirect(url_for('vulnerability_detail', vuln_id=vuln_id))

    now = datetime.utcnow()
    review_due = now + timedelta(days=SUPPRESSION_REVIEW_DAYS)
    cust = get_current_customer()

    # Record the determination as a rule, not just a flag on this row. Every
    # import writes new rows, so a row-only suppression lapsed at the next scan.
    # The rule persists and is re-applied after each import.
    scope = 'plugin' if request.form.get('scope') == 'plugin' else 'finding'
    rule = SuppressionRule(
        customer_id=cust.id if cust else None,
        scope=scope,
        plugin_id=vuln.plugin_id or None,
        plugin_name=vuln.plugin_name or None,
        asset=None if scope == 'plugin' else vuln.asset,
        reason=reason,
        created_by_id=current_user.id,
        created_at=now,
        review_due=review_due,
    )
    db.session.add(rule)
    db.session.commit()

    n = apply_suppression_rules(cust.id if cust else None)
    if scope == 'plugin':
        flash(f'{n:,} finding{"s" if n != 1 else ""} suppressed across every asset with '
              f'this detection, and the determination will be re-applied to future '
              f'imports. Review falls due {review_due.strftime("%Y-%m-%d")}.', 'success')
    else:
        flash(f'Finding suppressed, and the determination will be re-applied to future '
              f'imports. Review falls due {review_due.strftime("%Y-%m-%d")}.', 'success')
    return redirect(url_for('vulnerability_detail', vuln_id=vuln_id))


@app.route('/vulnerabilities/<int:vuln_id>/unsuppress', methods=['POST'])
@login_required
@customer_required
def vulnerability_unsuppress(vuln_id):
    """Reinstate a suppressed finding as active. Keeps the prior reason for audit."""
    vuln = db.get_or_404(Vulnerability, vuln_id)
    cust = get_current_customer()

    # Revoke any rule that covers this finding. Without it the flag would be
    # cleared here and set again by the next import, which looks like the
    # reinstatement silently failed.
    revoked = 0
    if cust:
        for rule in _active_suppression_rules(cust.id):
            covers = ((rule.scope == 'plugin' and rule.plugin_id == vuln.plugin_id)
                      or (rule.scope == 'asset' and rule.asset == vuln.asset)
                      or (rule.scope == 'finding' and rule.plugin_id == vuln.plugin_id
                          and rule.asset == vuln.asset))
            if covers:
                rule.revoked = True
                rule.revoked_at = datetime.utcnow()
                rule.revoked_by_id = current_user.id
                revoked += 1

    vuln.suppressed             = False
    vuln.suppression_review_due = None
    db.session.commit()

    if revoked:
        flash(f'Finding reinstated and {revoked} suppression rule'
              f'{"s" if revoked != 1 else ""} revoked, so it will not be '
              f'suppressed again on the next import.', 'warning')
    else:
        flash('Finding reinstated as active.', 'warning')
    return redirect(url_for('vulnerability_detail', vuln_id=vuln_id))


@app.route('/suppressions')
@login_required
@customer_required
def suppression_review():
    """
    Suppression review queue. NBL-IT-020 section 14 requires suppressions to be
    reviewed at least every six months; anything past its review date shows first.
    """
    # Deliberately not scoped to the latest import: a suppression recorded against
    # an earlier import must still surface for review rather than quietly disappear.
    latest = _latest_import()
    now    = datetime.utcnow()
    page   = request.args.get('page', 1, type=int)
    supp_import_ids = [i.id for i in _cust_scan_q().all()]

    if supp_import_ids:
        base = Vulnerability.query.filter(
            Vulnerability.suppressed == True,
            Vulnerability.scan_import_id.in_(supp_import_ids))
        # Counting in SQL rather than by materialising every suppressed finding:
        # a large tenant has tens of thousands, and the page only shows a page of
        # them. The table used to load and render the lot, which broke it.
        total_count   = base.count()
        overdue_count = base.filter(Vulnerability.suppression_review_due != None,
                                    Vulnerability.suppression_review_due <= now).count()
        undated_count = base.filter(Vulnerability.suppression_review_due == None).count()
        # Clamp rather than render an empty table for a page past the end.
        page = max(1, min(page, max(1, -(-total_count // 100))))
        pagination = (base
                      .order_by(Vulnerability.suppression_review_due.is_(None),
                                Vulnerability.suppression_review_due)
                      .paginate(page=page, per_page=100, error_out=False))
        rows = pagination.items
    else:
        total_count = overdue_count = undated_count = 0
        pagination = None
        rows = []

    cust = get_current_customer()
    rules = (SuppressionRule.query
             .filter_by(customer_id=cust.id if cust else None)
             .order_by(SuppressionRule.revoked,
                       SuppressionRule.review_due).all())
    return render_template('suppressions.html',
                           rows=rows, now=now,
                           pagination=pagination,
                           total_count=total_count,
                           rules=rules,
                           rules_active=sum(1 for r in rules if not r.revoked),
                           rules_overdue=sum(1 for r in rules if r.is_overdue),
                           overdue_count=overdue_count,
                           undated_count=undated_count,
                           review_days=SUPPRESSION_REVIEW_DAYS,
                           latest=latest)


@app.route('/suppressions/rules/<int:rule_id>/revoke', methods=['POST'])
@login_required
@customer_required
def suppression_rule_revoke(rule_id):
    """Revoke a determination and reinstate every finding it was suppressing."""
    cust = get_current_customer()
    rule = (SuppressionRule.query
            .filter_by(id=rule_id, customer_id=cust.id if cust else None).first() or abort(404))
    if rule.revoked:
        flash('That rule is already revoked.', 'warning')
        return redirect(url_for('suppression_review'))

    import_ids = [i.id for i in _cust_scan_q().all()]
    q = Vulnerability.query.filter(Vulnerability.scan_import_id.in_(import_ids),
                                   Vulnerability.suppressed == True)
    if rule.scope == 'plugin' and rule.plugin_id:
        q = q.filter(Vulnerability.plugin_id == rule.plugin_id)
    elif rule.scope == 'asset' and rule.asset:
        q = q.filter(Vulnerability.asset == rule.asset)
    elif rule.scope == 'finding':
        q = q.filter(Vulnerability.plugin_id == rule.plugin_id,
                     Vulnerability.asset == rule.asset)
    n = q.update({'suppressed': False, 'suppression_review_due': None},
                 synchronize_session=False)

    rule.revoked = True
    rule.revoked_at = datetime.utcnow()
    rule.revoked_by_id = current_user.id
    db.session.commit()
    flash(f'Rule revoked. {n:,} finding{"s" if n != 1 else ""} reinstated as active.', 'warning')
    return redirect(url_for('suppression_review'))


@app.route('/risk-acceptance/<int:entry_id>/revoke', methods=['POST'])
@login_required
def risk_acceptance_revoke(entry_id):
    entry = db.session.get(RiskAcceptance, entry_id) or abort(404)
    if not entry.revoked:
        entry.revoked = True
        entry.revoked_at = datetime.utcnow()
        entry.revoked_by_id = current_user.id
        db.session.commit()
        flash(f'Risk acceptance {entry.tag} has been revoked.', 'warning')
    return redirect(url_for('risk_acceptance'))


@app.route('/risk-acceptance/<int:entry_id>/delete', methods=['POST'])
@login_required
def risk_acceptance_delete(entry_id):
    if current_user.role != 'admin':
        abort(403)
    entry = db.session.get(RiskAcceptance, entry_id) or abort(404)
    tag = entry.tag
    db.session.delete(entry)
    db.session.commit()
    flash(f'Risk acceptance {tag} permanently deleted.', 'danger')
    return redirect(url_for('risk_acceptance'))


@app.route('/api/risk-acceptance/tags')
@login_required
def api_ra_tags():
    """Return active RA tags for a given asset / plugin_id combination."""
    asset     = request.args.get('asset', '')
    plugin_id = request.args.get('plugin_id', '')
    now = datetime.utcnow()

    q = _cust_ra_q().filter_by(revoked=False).filter(
        or_(RiskAcceptance.expires_at == None, RiskAcceptance.expires_at > now)
    )
    results = []
    for e in q.all():
        asset_match  = (not e.asset) or (e.asset == asset)
        plugin_match = (e.scope == 'asset') or (not e.plugin_id) or (e.plugin_id == plugin_id)
        if asset_match and plugin_match:
            results.append({'tag': e.tag, 'scope': e.scope,
                            'reason': e.reason, 'expires_at': e.expires_at.isoformat() if e.expires_at else None})
    return jsonify(results)


# ── Admin ─────────────────────────────────────────────────────────────────────

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users     = User.query.order_by(User.created_at).all()
    customers = Customer.query.filter_by(active=True).order_by(Customer.name).all()
    return render_template('admin_users.html', users=users, customers=customers)


def _wants_json():
    """True when the request came from fetch() rather than a plain form post."""
    return request.headers.get('X-Requested-With') == 'fetch' or \
           request.accept_mimetypes.best == 'application/json'


def _user_json(u):
    return {
        'id':         u.id,
        'username':   u.username,
        'email':      u.email or '',
        'role':       u.role,
        'is_active':  u.is_active,
        'last_login': u.last_login.strftime('%Y-%m-%d %H:%M') if u.last_login else None,
        'customers':  [{'id': c.id, 'name': c.name} for c in u.customers],
        'is_self':    u.id == current_user.id,
    }


@app.route('/api/admin/users')
@login_required
@admin_required
def api_admin_users():
    users     = User.query.order_by(User.created_at).all()
    customers = Customer.query.filter_by(active=True).order_by(Customer.name).all()
    return jsonify({
        'users':     [_user_json(u) for u in users],
        'customers': [{'id': c.id, 'name': c.name} for c in customers],
    })


@app.route('/admin/users/add', methods=['POST'])
@login_required
@admin_required
def admin_add_user():
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip() or None
    password = request.form.get('password', '')
    role = request.form.get('role', 'viewer')

    customer_ids = request.form.getlist('customer_ids')

    error = None
    if not username or not password:
        error = 'Username and password are required.'
    elif len(password) < 6:
        error = 'Password must be at least 6 characters.'
    elif User.query.filter_by(username=username).first():
        error = f'Username "{username}" already exists.'

    if error:
        if _wants_json():
            return jsonify({'ok': False, 'message': error}), 400
        flash(error, 'danger')
        return redirect(url_for('admin_users'))

    u = User(username=username, email=email, role=role)
    u.set_password(password)
    db.session.add(u)
    db.session.flush()   # get u.id before adding associations
    for cid in customer_ids:
        try:
            cid_int = int(cid)
            if not UserCustomer.query.filter_by(user_id=u.id, customer_id=cid_int).first():
                db.session.add(UserCustomer(user_id=u.id, customer_id=cid_int))
        except (ValueError, TypeError):
            pass
    db.session.commit()
    assigned = len(customer_ids)
    msg = (f'User "{username}" created with role {role}' +
           (f' and assigned to {assigned} customer(s).' if assigned else ' (no customers assigned yet).'))
    if _wants_json():
        return jsonify({'ok': True, 'message': msg, 'user': _user_json(u)})
    flash(msg, 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/toggle', methods=['POST'])
@login_required
@admin_required
def admin_toggle_user(user_id):
    u = db.get_or_404(User, user_id)
    if u.id == current_user.id:
        if _wants_json():
            return jsonify({'ok': False, 'message': 'You cannot deactivate your own account.'}), 400
        flash('You cannot deactivate your own account.', 'danger')
    else:
        u.is_active = not u.is_active
        db.session.commit()
        msg = f'User "{u.username}" {"activated" if u.is_active else "deactivated"}.'
        if _wants_json():
            return jsonify({'ok': True, 'message': msg, 'user': _user_json(u)})
        flash(msg, 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/reset', methods=['POST'])
@login_required
@admin_required
def admin_reset_password(user_id):
    u = db.get_or_404(User, user_id)
    pw = request.form.get('new_password', '')
    if len(pw) < 6:
        if _wants_json():
            return jsonify({'ok': False, 'message': 'Password must be at least 6 characters.'}), 400
        flash('Password must be at least 6 characters.', 'danger')
    else:
        u.set_password(pw)
        db.session.commit()
        msg = f'Password reset for "{u.username}".'
        if _wants_json():
            return jsonify({'ok': True, 'message': msg, 'user': _user_json(u)})
        flash(msg, 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/role', methods=['POST'])
@login_required
@admin_required
def admin_change_role(user_id):
    u = db.get_or_404(User, user_id)
    if u.id == current_user.id:
        if _wants_json():
            return jsonify({'ok': False, 'message': 'Cannot change your own role.'}), 400
        flash('Cannot change your own role.', 'danger')
    else:
        u.role = request.form.get('role', 'viewer')
        db.session.commit()
        msg = f'Role updated for "{u.username}".'
        if _wants_json():
            return jsonify({'ok': True, 'message': msg, 'user': _user_json(u)})
        flash(msg, 'success')
    return redirect(url_for('admin_users'))


# ── Admin: Customers ──────────────────────────────────────────────────────────

@app.route('/admin/customers')
@login_required
@admin_required
def admin_customers():
    customers = Customer.query.order_by(Customer.name).all()
    users     = User.query.order_by(User.username).all()
    # Credential files live beside the application and are never in version
    # control, so offer whatever this host actually has rather than a fixed list.
    env_files = sorted(f for f in os.listdir(APP_ROOT)
                       if f.startswith('.env') and f not in ('.env.example',))
    return render_template('admin_customers.html', customers=customers,
                           users=users, env_files=env_files,
                           scanners=Customer.SCANNERS)


@app.route('/admin/customers/add', methods=['POST'])
@login_required
@admin_required
def admin_add_customer():
    name = request.form.get('name', '').strip()
    if not name:
        flash('Customer name is required.', 'danger')
    elif Customer.query.filter_by(name=name).first():
        flash(f'Customer "{name}" already exists.', 'danger')
    else:
        c = Customer(name=name)
        db.session.add(c)
        db.session.commit()
        flash(f'Customer "{name}" created.', 'success')
    return redirect(url_for('admin_customers'))


@app.route('/admin/customers/<int:customer_id>/toggle', methods=['POST'])
@login_required
@admin_required
def admin_toggle_customer(customer_id):
    c = db.get_or_404(Customer, customer_id)
    c.active = not c.active
    db.session.commit()
    flash(f'Customer "{c.name}" {"activated" if c.active else "deactivated"}.', 'success')
    return redirect(url_for('admin_customers'))


@app.route('/admin/customers/<int:customer_id>/rename', methods=['POST'])
@login_required
@admin_required
def admin_rename_customer(customer_id):
    c    = db.get_or_404(Customer, customer_id)
    name = request.form.get('name', '').strip()
    if not name:
        flash('Name is required.', 'danger')
    elif Customer.query.filter(Customer.name == name, Customer.id != customer_id).first():
        flash(f'Name "{name}" is already taken.', 'danger')
    else:
        c.name = name
        db.session.commit()
        flash('Customer renamed.', 'success')
    return redirect(url_for('admin_customers'))


@app.route('/admin/customers/<int:customer_id>/scanner', methods=['POST'])
@login_required
@admin_required
def admin_customer_scanner(customer_id):
    c       = db.get_or_404(Customer, customer_id)
    scanner = request.form.get('scanner', '').strip()
    env     = request.form.get('scanner_env', '').strip()
    args    = request.form.get('scanner_args', '').strip()

    if scanner and scanner not in Customer.SCANNERS:
        flash('Unknown scanner.', 'danger')
        return redirect(url_for('admin_customers'))
    # A missing credential file would only surface as a failed job minutes later,
    # so reject it here where the administrator can still fix it.
    if scanner and env and not os.path.exists(os.path.join(APP_ROOT, env)):
        flash(f'No such credential file: {env}', 'danger')
        return redirect(url_for('admin_customers'))

    c.scanner      = scanner or None
    c.scanner_env  = env or None
    c.scanner_args = args or None
    db.session.commit()
    flash(f'Scanner settings saved for {c.name}.', 'success')
    return redirect(url_for('admin_customers'))


@app.route('/admin/customers/<int:customer_id>/users/add', methods=['POST'])
@login_required
@admin_required
def admin_customer_add_user(customer_id):
    c      = db.get_or_404(Customer, customer_id)
    uid    = request.form.get('user_id', type=int)
    u      = db.get_or_404(User, uid)
    exists = UserCustomer.query.filter_by(user_id=uid, customer_id=customer_id).first()
    if not exists:
        db.session.add(UserCustomer(user_id=uid, customer_id=customer_id))
        db.session.commit()
        msg = f'Added {u.username} to {c.name}.'
        if _wants_json():
            return jsonify({'ok': True, 'message': msg, 'user': _user_json(u)})
        flash(msg, 'success')
    else:
        if _wants_json():
            return jsonify({'ok': False, 'message': f'{u.username} already has access to {c.name}.'}), 400
        flash(f'{u.username} already has access to {c.name}.', 'warning')
    return redirect(url_for('admin_customers'))


@app.route('/admin/customers/<int:customer_id>/users/<int:user_id>/remove', methods=['POST'])
@login_required
@admin_required
def admin_customer_remove_user(customer_id, user_id):
    c  = db.get_or_404(Customer, customer_id)
    uc = UserCustomer.query.filter_by(user_id=user_id, customer_id=customer_id).first()
    if uc:
        db.session.delete(uc)
        db.session.commit()
        if _wants_json():
            u = db.session.get(User, user_id)
            return jsonify({'ok': True, 'message': f'Removed {u.username} from {c.name}.',
                            'user': _user_json(u)})
        flash(f'Removed user from {c.name}.', 'success')
    elif _wants_json():
        return jsonify({'ok': False, 'message': 'Assignment not found.'}), 404
    return redirect(url_for('admin_customers'))


# ── Executive Summary ────────────────────────────────────────────────────────

@app.route('/executive')
@login_required
@customer_required
def executive():
    # ── Import selector ───────────────────────────────────────────────────────
    req_import_id    = request.args.get('import_id', type=int)
    # Defaults ON here: the executive view is the reported position, and accepted
    # risk is formally signed off, so it should not inflate the headline numbers.
    # Turning the switch off sends exclude_accepted=0 explicitly (see _navUrl).
    exclude_accepted = request.args.get('exclude_accepted', '1') == '1'
    # 'findings' counts every affected host/package (the remediation workload);
    # 'cves' counts distinct CVEs rated by their worst instance, which is how
    # scanner consoles headline the same estate.
    count_by = 'cves' if request.args.get('count_by') == 'cves' else 'findings'

    latest = _latest_import()
    if not latest:
        return render_template('executive.html', no_data=True)

    current_import = (db.session.get(ScanImport, req_import_id) if req_import_id else latest) or latest

    # Pre-fetch active RAs once; build exclusion criteria and ID set
    active_ras       = _fetch_active_ras() if exclude_accepted else []
    excl_assets, excl_findings = _ra_criteria(active_ras)
    excluded_ids     = _accepted_vuln_ids(current_import.id, active_ras) if active_ras else set()

    def _excl(q):
        """Apply accepted-risk exclusion filter using asset/plugin criteria (no large IN list)."""
        return _apply_ra_filter(q, excl_assets, excl_findings)

    now = datetime.utcnow()
    SEVS = ['Critical', 'High', 'Medium', 'Low']
    AT_RISK_BUFFER = 7

    # ── Severity counts (active, non-suppressed) ──────────────────────────────
    sev_q = (db.session.query(Vulnerability.risk_factor, func.count(Vulnerability.id))
             .filter_by(scan_import_id=current_import.id, suppressed=False))
    sev_rows = _excl(sev_q).group_by(Vulnerability.risk_factor).all()
    sev_findings = {k: 0 for k in SEVS + ['Informational']}
    for rf, cnt in sev_rows:
        if rf in sev_findings:
            sev_findings[rf] = cnt

    # CVE-level view: one entry per CVE, rated by its worst instance on the estate.
    cve_sub = (db.session.query(Vulnerability.vulnerability_id.label('cve'),
                                func.max(Vulnerability.severity_level).label('worst'))
               .filter_by(scan_import_id=current_import.id, suppressed=False)
               .filter(Vulnerability.vulnerability_id.isnot(None),
                       Vulnerability.vulnerability_id != ''))
    cve_sub = _excl(cve_sub).group_by(Vulnerability.vulnerability_id).subquery()
    _lvl_name = {4: 'Critical', 3: 'High', 2: 'Medium', 1: 'Low', 0: 'Informational'}
    sev_cves = {k: 0 for k in SEVS + ['Informational']}
    for worst, n in (db.session.query(cve_sub.c.worst, func.count())
                     .group_by(cve_sub.c.worst).all()):
        name = _lvl_name.get(worst)
        if name in sev_cves:
            sev_cves[name] = n

    sev = sev_cves if count_by == 'cves' else sev_findings
    total_active   = sum(sev.values())
    total_findings = sum(sev_findings.values())
    total_cves     = sum(sev_cves.values())

    # ── CVSS average ──────────────────────────────────────────────────────────
    avg_cvss_q = (db.session.query(func.avg(Vulnerability.cvss_v3_score))
                  .filter_by(scan_import_id=current_import.id, suppressed=False)
                  .filter(Vulnerability.cvss_v3_score.isnot(None)))
    avg_cvss_row = _excl(avg_cvss_q).scalar()
    avg_cvss = round(float(avg_cvss_row), 1) if avg_cvss_row else 0.0

    # ── Week-over-week delta ──────────────────────────────────────────────────
    prev = (_cust_scan_q()
            .filter(ScanImport.imported_at < current_import.imported_at)
            .order_by(desc(ScanImport.imported_at)).first())
    delta = {}
    prev_sev = {k: 0 for k in SEVS}
    if prev:
        prev_ids = {v.vulnerability_id for v in
                    Vulnerability.query.filter_by(scan_import_id=prev.id)
                    .with_entities(Vulnerability.vulnerability_id)}
        cur_ids  = {v.vulnerability_id for v in
                    _excl(Vulnerability.query.filter_by(scan_import_id=current_import.id))
                    .with_entities(Vulnerability.vulnerability_id)}
        delta = {'new': len(cur_ids - prev_ids), 'resolved': len(prev_ids - cur_ids)}
        prev_sev_rows = (db.session.query(Vulnerability.risk_factor, func.count(Vulnerability.id))
                         .filter_by(scan_import_id=prev.id, suppressed=False)
                         .group_by(Vulnerability.risk_factor).all())
        for rf, cnt in prev_sev_rows:
            if rf in prev_sev:
                prev_sev[rf] = cnt

    # ── SLA status for all active findings ───────────────────────────────────
    all_vulns_q = (db.session.query(Vulnerability.asset, Vulnerability.risk_factor,
                                    Vulnerability.first_seen)
                   .filter(Vulnerability.scan_import_id == current_import.id,
                           Vulnerability.suppressed == False,
                           Vulnerability.risk_factor.in_(SEVS)))
    all_vulns = _excl(all_vulns_q).all()

    sla_counts = {'Breached': 0, 'At Risk': 0, 'On Track': 0}
    assets_with_breach = set()
    assets_with_critical_high = set()
    ext_assets = _internet_facing_assets()
    for v in all_vulns:
        days_open = (now - v.first_seen).days if v.first_seen else None
        sla       = _sla_for(v.risk_factor, v.asset, ext_assets)
        if days_open is not None and sla is not None:
            if days_open > sla:
                sla_counts['Breached'] += 1
                assets_with_breach.add(v.asset)
            elif days_open >= sla - AT_RISK_BUFFER:
                sla_counts['At Risk'] += 1
            else:
                sla_counts['On Track'] += 1
        if v.risk_factor in ('Critical', 'High'):
            assets_with_critical_high.add(v.asset)

    total_sla = sum(sla_counts.values()) or 1
    breach_pct = round(sla_counts['Breached'] / total_sla * 100)
    compliance_pct = round(sla_counts['On Track'] / total_sla * 100)

    # ── Risk grade (0-100 score → A-F) ───────────────────────────────────────
    score = (
        min(30, sev['Critical'] * 0.5) +
        min(20, sev['High'] * 0.2) +
        min(30, breach_pct * 0.3) +
        min(20, max(0.0, avg_cvss - 4.0) * 3.33)
    )
    score = round(min(100, score))
    if score <= 20:
        grade, grade_color = 'A', '#238636'
    elif score <= 40:
        grade, grade_color = 'B', '#2ea043'
    elif score <= 60:
        grade, grade_color = 'C', '#d29922'
    elif score <= 75:
        grade, grade_color = 'D', '#e67e00'
    else:
        grade, grade_color = 'F', '#da3633'

    # ── Distinct asset count ──────────────────────────────────────────────────
    asset_count_q = (db.session.query(func.count(func.distinct(Vulnerability.asset)))
                     .filter_by(scan_import_id=current_import.id, suppressed=False))
    asset_count = _excl(asset_count_q).scalar() or 0

    # ── Top 8 assets by risk score ────────────────────────────────────────────
    top_assets_q = (db.session.query(
        Vulnerability.asset, Vulnerability.ip_address,
        func.count(Vulnerability.id).label('total'),
        _risk_score_expr().label('risk_score'),
        _sev_count('Critical').label('critical'),
        _sev_count('High').label('high'),
        _sev_count('Medium').label('medium'),
        _sev_count('Low').label('low'),
    ).filter_by(scan_import_id=current_import.id, suppressed=False))
    top_assets = (_excl(top_assets_q)
                  .group_by(Vulnerability.asset)
                  .order_by(desc('risk_score'))
                  .limit(8).all())

    assets_chart = [{'asset': a.asset, 'risk_score': float(a.risk_score or 0),
                     'critical': a.critical or 0, 'high': a.high or 0,
                     'medium': a.medium or 0}
                    for a in top_assets]

    # ── Top 10 priority vulnerabilities (critical/high, most hosts) ───────────
    top_vulns_q = (db.session.query(
        Vulnerability.plugin_id,
        Vulnerability.plugin_name,
        Vulnerability.vulnerability_id,
        Vulnerability.risk_factor,
        Vulnerability.cvss_v3_score,
        func.count(Vulnerability.id).label('cnt'),
        func.count(func.distinct(Vulnerability.asset)).label('assets'),
        # A representative row id so the table can link to the detail page, the
        # same destination as the Vulnerabilities list. Without it these rows
        # only had a plugin name to work with and had to guess a target.
        func.min(Vulnerability.id).label('example_id'),
    ).filter(
        Vulnerability.scan_import_id == current_import.id,
        Vulnerability.suppressed == False,
        Vulnerability.risk_factor.in_(['Critical', 'High']),
    ))
    top_vulns = (_excl(top_vulns_q)
                 .group_by(Vulnerability.plugin_name, Vulnerability.plugin_id,
                           Vulnerability.vulnerability_id,
                           Vulnerability.risk_factor, Vulnerability.cvss_v3_score)
                 .order_by(desc(Vulnerability.risk_factor == 'Critical'), desc('assets'))
                 .limit(10).all())

    # ── Historical trend (all imports) ───────────────────────────────────────
    trend_imports = _cust_scan_q().order_by(ScanImport.imported_at).all()
    trend_data = []
    for imp in trend_imports:
        label = imp.report_date.isoformat() if imp.report_date else imp.imported_at.strftime('%Y-%m-%d')
        row = {'date': label, 'import_id': imp.id}
        for s in SEVS:
            q = Vulnerability.query.filter_by(scan_import_id=imp.id,
                                              risk_factor=s, suppressed=False)
            if excl_assets or excl_findings:
                q = _apply_ra_filter(q, excl_assets, excl_findings)
            row[s] = q.count()
        trend_data.append(row)

    # ── Accepted risk count (for badge display) ───────────────────────────────
    now_dt = datetime.utcnow()
    accepted_count = _cust_ra_q().filter_by(revoked=False).filter(
        or_(RiskAcceptance.expires_at == None, RiskAcceptance.expires_at > now_dt)
    ).count()

    # ── Auto-generated key findings ───────────────────────────────────────────
    findings_bullets = []
    if sev['Critical'] > 0:
        findings_bullets.append(
            f"{sev['Critical']:,} critical-severity finding{'s' if sev['Critical'] != 1 else ''} require"
            f"{'s' if sev['Critical'] == 1 else ''} immediate remediation (SLA: 7 days)."
        )
    if sev['High'] > 0:
        findings_bullets.append(
            f"{sev['High']:,} high-severity finding{'s' if sev['High'] != 1 else ''} must be "
            f"remediated within 30 days."
        )
    if sla_counts['Breached'] > 0:
        findings_bullets.append(
            f"{sla_counts['Breached']:,} finding{'s' if sla_counts['Breached'] != 1 else ''} "
            f"ha{'ve' if sla_counts['Breached'] != 1 else 's'} breached SLA — immediate action required."
        )
    if assets_with_critical_high:
        findings_bullets.append(
            f"{len(assets_with_critical_high):,} asset{'s' if len(assets_with_critical_high) != 1 else ''} "
            f"exposed to critical or high severity vulnerabilities."
        )
    if top_vulns:
        tv = top_vulns[0]
        findings_bullets.append(
            f"Most prevalent risk: \"{tv.plugin_name or tv.vulnerability_id}\" affects {tv.assets:,} "
            f"asset{'s' if tv.assets != 1 else ''} ({tv.risk_factor})."
        )
    if avg_cvss >= 7.0:
        findings_bullets.append(
            f"Average CVSS score of {avg_cvss} indicates a high-severity threat landscape across the environment."
        )
    if delta.get('new', 0) > 0:
        findings_bullets.append(
            f"{delta['new']:,} new finding{'s' if delta['new'] != 1 else ''} introduced since the previous scan."
        )
    if delta.get('resolved', 0) > 0:
        findings_bullets.append(
            f"{delta['resolved']:,} finding{'s' if delta['resolved'] != 1 else ''} resolved since the previous scan."
        )
    if exclude_accepted and excluded_ids:
        findings_bullets.append(
            f"{len(excluded_ids):,} finding{'s' if len(excluded_ids) != 1 else ''} excluded from view — covered by accepted risk."
        )

    all_imports = _cust_scan_q().order_by(desc(ScanImport.imported_at)).all()

    return render_template('executive.html',
        no_data=False,
        latest=current_import,
        all_imports=all_imports,
        exclude_accepted=exclude_accepted,
        accepted_count=accepted_count,
        count_by=count_by,
        sev_findings=sev_findings,
        sev_cves=sev_cves,
        total_findings=total_findings,
        total_cves=total_cves,
        excluded_count=len(excluded_ids),
        # headline numbers
        total_active=total_active,
        sev=sev, prev_sev=prev_sev,
        avg_cvss=avg_cvss,
        asset_count=asset_count,
        assets_at_risk=len(assets_with_critical_high),
        assets_breached=len(assets_with_breach),
        # risk grade
        grade=grade, grade_color=grade_color, score=score,
        # delta
        delta=delta,
        # SLA
        sla_counts=sla_counts,
        breach_pct=breach_pct,
        compliance_pct=compliance_pct,
        # tables / charts
        top_assets=top_assets,
        assets_chart_json=json.dumps(assets_chart),
        top_vulns=top_vulns,
        trend_data_json=json.dumps(trend_data),
        # bullets
        findings_bullets=findings_bullets,
    )


# ── API (JSON) ────────────────────────────────────────────────────────────────

@app.route('/api/severity-over-time')
@login_required
@customer_required
def api_severity_over_time():
    imports = _cust_scan_q().order_by(ScanImport.imported_at).all()
    data = []
    for imp in imports:
        label = imp.report_date.isoformat() if imp.report_date else imp.imported_at.strftime('%Y-%m-%d')
        row = {'date': label}
        for s in ('Critical', 'High', 'Medium', 'Low'):
            row[s] = Vulnerability.query.filter_by(scan_import_id=imp.id, risk_factor=s).count()
        data.append(row)
    return jsonify(data)


# ── Error handlers ────────────────────────────────────────────────────────────

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, message='Access Forbidden'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, message='Page Not Found'), 404


@app.errorhandler(413)
def too_large(e):
    return render_template('error.html', code=413, message='File Too Large (max 200MB)'), 413


# ── API: assets for a vulnerability ──────────────────────────────────────────

@app.route('/api/vuln-assets')
@login_required
@customer_required
def api_vuln_assets():
    import_id      = request.args.get('import_id', type=int)
    plugin_name    = request.args.get('plugin_name', '').strip()
    vulnerability_id = request.args.get('vulnerability_id', '').strip()

    if not import_id:
        latest = _latest_import()
        import_id = latest.id if latest else None

    q = Vulnerability.query.filter_by(scan_import_id=import_id, suppressed=False)
    if plugin_name:
        q = q.filter_by(plugin_name=plugin_name)
    elif vulnerability_id:
        q = q.filter_by(vulnerability_id=vulnerability_id)
    else:
        return jsonify([])

    rows = q.with_entities(
        Vulnerability.asset,
        Vulnerability.ip_address,
        Vulnerability.first_seen,
        Vulnerability.last_seen,
        Vulnerability.port,
    ).distinct().order_by(Vulnerability.asset).all()

    return jsonify([{
        'asset':      r.asset,
        'ip':         r.ip_address or '',
        'first_seen': r.first_seen.strftime('%Y-%m-%d') if r.first_seen else '',
        'last_seen':  r.last_seen.strftime('%Y-%m-%d')  if r.last_seen  else '',
        'port':       r.port or '',
    } for r in rows])


# ── News / RSS ────────────────────────────────────────────────────────────────

_feed_cache = {}          # {feed_id: (timestamp, entries)}
_FEED_TTL   = 1800        # 30 minutes


def _fetch_feed(feed):
    """Return list of entry dicts for a feed, using in-memory cache."""
    cached = _feed_cache.get(feed.id)
    if cached and (time.time() - cached[0]) < _FEED_TTL:
        return cached[1]
    parsed = feedparser.parse(feed.url)
    entries = []
    for e in parsed.entries[:20]:
        published = None
        if hasattr(e, 'published_parsed') and e.published_parsed:
            published = datetime(*e.published_parsed[:6])
        elif hasattr(e, 'updated_parsed') and e.updated_parsed:
            published = datetime(*e.updated_parsed[:6])
        summary = ''
        if hasattr(e, 'summary'):
            # Strip HTML tags from summary
            summary = re.sub(r'<[^>]+>', '', e.summary or '')[:300]
        entries.append({
            'title':     getattr(e, 'title', 'Untitled'),
            'link':      getattr(e, 'link', '#'),
            'published': published,
            'summary':   summary,
            'feed_name': feed.name,
            'feed_id':   feed.id,
        })
    _feed_cache[feed.id] = (time.time(), entries)
    return entries


@app.route('/news')
@login_required
def news():
    feeds = NewsFeed.query.order_by(NewsFeed.created_at).all()
    active_feeds = [f for f in feeds if f.active]
    all_entries = []
    fetch_errors = []
    for feed in active_feeds:
        try:
            all_entries.extend(_fetch_feed(feed))
        except Exception as e:
            fetch_errors.append(f'{feed.name}: {e}')
    all_entries.sort(key=lambda x: x['published'] or datetime.min, reverse=True)
    return render_template('news.html', feeds=feeds, entries=all_entries,
                           fetch_errors=fetch_errors)


@app.route('/admin/feeds', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_feeds():
    if request.method == 'POST':
        action = request.form.get('action')
        feed_id = request.form.get('feed_id', type=int)

        if action == 'add':
            name = request.form.get('name', '').strip()
            url  = request.form.get('url', '').strip()
            if name and url:
                if not NewsFeed.query.filter_by(url=url).first():
                    db.session.add(NewsFeed(name=name, url=url))
                    db.session.commit()
                    flash(f'Feed "{name}" added.', 'success')
                else:
                    flash('A feed with that URL already exists.', 'warning')
            else:
                flash('Name and URL are required.', 'warning')

        elif action == 'toggle' and feed_id:
            feed = db.get_or_404(NewsFeed, feed_id)
            feed.active = not feed.active
            db.session.commit()
            _feed_cache.pop(feed_id, None)
            flash(f'Feed "{feed.name}" {"enabled" if feed.active else "disabled"}.', 'success')

        elif action == 'delete' and feed_id:
            feed = db.get_or_404(NewsFeed, feed_id)
            name = feed.name
            db.session.delete(feed)
            db.session.commit()
            _feed_cache.pop(feed_id, None)
            flash(f'Feed "{name}" deleted.', 'success')

        elif action == 'refresh' and feed_id:
            _feed_cache.pop(feed_id, None)
            flash('Feed cache cleared — will refresh on next load.', 'success')

        return redirect(url_for('admin_feeds'))

    feeds = NewsFeed.query.order_by(NewsFeed.created_at).all()
    return render_template('admin_feeds.html', feeds=feeds)


# ── Bootstrap ─────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.first():
            admin = User(username='admin', email='admin@local', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print('Created default admin: admin / admin123')
        if not NewsFeed.query.first():
            db.session.add(NewsFeed(
                name='Unit 42 — Palo Alto Networks',
                url='https://unit42.paloaltonetworks.com/feed/',
            ))
            db.session.commit()
            print('Seeded default news feed: Unit 42')
    app.run(debug=True, port=5001)
