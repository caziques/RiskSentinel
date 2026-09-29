from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class Customer(db.Model):
    __tablename__ = 'customers'
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(128), unique=True, nullable=False)
    active      = db.Column(db.Boolean, default=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    # Which scanner API backs this customer, so the Update page can pull directly
    # rather than waiting for the weekly cron. Credentials stay in the env file:
    # only its name is stored here, never a secret.
    scanner      = db.Column(db.String(32), nullable=True)    # levelblue | cortex
    scanner_env  = db.Column(db.String(128), nullable=True)   # e.g. .env.cortex.mcr
    scanner_args = db.Column(db.String(256), nullable=True)   # e.g. --days 30

    SCANNERS = {
        'levelblue': ('LevelBlue / USM Anywhere', 'levelblue_import.py'),
        'cortex':    ('Palo Alto Cortex',         'cortex_import.py'),
    }

    @property
    def scanner_label(self):
        return self.SCANNERS.get(self.scanner, ('Not configured', None))[0]

    @property
    def scanner_script(self):
        return self.SCANNERS.get(self.scanner, (None, None))[1]

    @property
    def can_api_update(self):
        return bool(self.scanner and self.scanner_script)

    scan_imports     = db.relationship('ScanImport',     backref='customer', lazy='dynamic')
    risk_acceptances = db.relationship('RiskAcceptance', backref='customer', lazy='dynamic')
    asset_groups     = db.relationship('AssetGroup',     backref='customer', lazy='dynamic')

    def __repr__(self):
        return f'<Customer {self.name}>'


class UserCustomer(db.Model):
    __tablename__ = 'user_customers'
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('users.id'),     nullable=False, index=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False, index=True)
    user        = db.relationship('User',     backref='customer_links')
    customer    = db.relationship('Customer', backref='user_links')
    __table_args__ = (db.UniqueConstraint('user_id', 'customer_id'),)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='viewer')  # admin, analyst, viewer
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    # Direct many-to-many relationship to Customer via UserCustomer join table
    customers = db.relationship(
        'Customer',
        secondary='user_customers',
        primaryjoin='User.id == UserCustomer.user_id',
        secondaryjoin='UserCustomer.customer_id == Customer.id',
        viewonly=True,
        order_by='Customer.name',
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class ScanImport(db.Model):
    __tablename__ = 'scan_imports'
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=True, index=True)
    filename = db.Column(db.String(256))
    report_date = db.Column(db.Date)
    imported_at = db.Column(db.DateTime, default=datetime.utcnow)
    imported_by_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    record_count = db.Column(db.Integer, default=0)
    notes = db.Column(db.Text)

    imported_by = db.relationship('User', backref='imports')
    vulnerabilities = db.relationship('Vulnerability', backref='scan_import', lazy='dynamic',
                                      cascade='all, delete-orphan')


class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'
    id = db.Column(db.Integer, primary_key=True)
    scan_import_id = db.Column(db.Integer, db.ForeignKey('scan_imports.id'), index=True)
    vulnerability_id = db.Column(db.String(256), index=True)
    suppressed = db.Column(db.Boolean, default=False)
    # NBL-IT-020 section 14: false positive determinations must be auditable and re-reviewed.
    suppression_reason     = db.Column(db.Text)
    suppressed_at          = db.Column(db.DateTime)
    suppressed_by_id       = db.Column(db.Integer, db.ForeignKey('users.id'))
    suppression_review_due = db.Column(db.DateTime)
    asset = db.Column(db.String(256), index=True)
    ip_address = db.Column(db.String(64))
    source = db.Column(db.String(128))
    labels = db.Column(db.String(512))
    first_seen = db.Column(db.DateTime)
    last_seen = db.Column(db.DateTime)
    cvss_v3_severity = db.Column(db.String(20))
    cvss_v3_score = db.Column(db.Float)
    cvss_v4_severity = db.Column(db.String(20))
    cvss_v4_score = db.Column(db.Float)
    available_patches = db.Column(db.Text)
    affected_software = db.Column(db.Text)
    # Parsed from JSON description
    plugin_id = db.Column(db.String(32), index=True)
    plugin_name = db.Column(db.String(512))
    plugin_family = db.Column(db.String(128))
    risk_factor = db.Column(db.String(20), index=True)  # None/Low/Medium/High/Critical
    severity_level = db.Column(db.Integer, index=True)  # 0-4
    synopsis = db.Column(db.Text)
    description = db.Column(db.Text)
    solution = db.Column(db.Text)
    port = db.Column(db.String(16))
    protocol = db.Column(db.String(16))
    plugin_output = db.Column(db.Text)
    cpe = db.Column(db.Text)

    SEVERITY_ORDER = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'None': 0}
    SEVERITY_COLOR = {
        'Critical': 'danger',
        'High': 'warning',
        'Medium': 'info',
        'Low': 'success',
        'None': 'secondary',
    }

    @property
    def severity_badge(self):
        return self.SEVERITY_COLOR.get(self.risk_factor, 'secondary')

    @property
    def risk_score(self):
        weights = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1, 'None': 0}
        if self.cvss_v3_score:
            return self.cvss_v3_score
        return weights.get(self.risk_factor, 0)


class RiskAcceptance(db.Model):
    __tablename__ = 'risk_acceptances'
    id               = db.Column(db.Integer, primary_key=True)
    customer_id      = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=True, index=True)
    tag              = db.Column(db.String(20), unique=True, nullable=False, index=True)
    scope            = db.Column(db.String(20), nullable=False)   # 'asset' | 'finding'
    asset            = db.Column(db.String(256), nullable=True, index=True)
    plugin_id        = db.Column(db.String(64),  nullable=True, index=True)
    plugin_name      = db.Column(db.String(512), nullable=True)
    vulnerability_id = db.Column(db.String(128), nullable=True)
    risk_factor      = db.Column(db.String(32),  nullable=True)
    reason           = db.Column(db.Text, nullable=False)
    notes            = db.Column(db.Text, nullable=True)
    accepted_by_id   = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    accepted_by      = db.relationship('User', foreign_keys=[accepted_by_id],
                                       backref='risk_acceptances')
    accepted_at      = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at       = db.Column(db.DateTime, nullable=True)
    revoked          = db.Column(db.Boolean, default=False)
    revoked_at       = db.Column(db.DateTime, nullable=True)
    revoked_by_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    revoked_by       = db.relationship('User', foreign_keys=[revoked_by_id])
    group_id         = db.Column(db.Integer, db.ForeignKey('asset_groups.id'), nullable=True, index=True)
    group            = db.relationship('AssetGroup', foreign_keys=[group_id])

    @property
    def status(self):
        if self.revoked:
            return 'Revoked'
        if self.expires_at and self.expires_at < datetime.utcnow():
            return 'Expired'
        return 'Active'

    @property
    def expiring_soon(self):
        """True if active and expires within 30 days."""
        if self.revoked or not self.expires_at:
            return False
        return 0 <= (self.expires_at - datetime.utcnow()).days <= 30


class NewsFeed(db.Model):
    __tablename__ = 'news_feeds'
    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(256), nullable=False)
    url        = db.Column(db.String(512), nullable=False, unique=True)
    active     = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AssetGroup(db.Model):
    __tablename__ = 'asset_groups'
    id            = db.Column(db.Integer, primary_key=True)
    customer_id   = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=True, index=True)
    name          = db.Column(db.String(128), unique=True, nullable=False)
    description   = db.Column(db.Text, nullable=True)
    color         = db.Column(db.String(16), default='#1f6feb')
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_by    = db.relationship('User', foreign_keys=[created_by_id])
    members       = db.relationship('AssetGroupMember', backref='group',
                                    lazy='dynamic', cascade='all, delete-orphan')


class AssetGroupMember(db.Model):
    __tablename__ = 'asset_group_members'
    id         = db.Column(db.Integer, primary_key=True)
    group_id   = db.Column(db.Integer, db.ForeignKey('asset_groups.id'),
                           nullable=False, index=True)
    asset_name = db.Column(db.String(256), nullable=False)
    added_at   = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('group_id', 'asset_name'),)


class RemediationProject(db.Model):
    """
    A time-boxed bundle of remediation work: a set of solutions to apply across a
    set of assets, owned by someone, with a due date.

    Modelled on the InsightVM remediation-project idea, but scanner-agnostic so it
    works across USM, Rapid7 and Cortex alike. Work is grouped by solution rather
    than by finding, because one package upgrade often clears many CVEs on many
    hosts, and that is the unit a remediation team actually actions.
    """
    __tablename__ = 'remediation_projects'
    STATUSES = ('Open', 'Closed')

    id            = db.Column(db.Integer, primary_key=True)
    customer_id   = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=True, index=True)
    name          = db.Column(db.String(200), nullable=False)
    description   = db.Column(db.Text, nullable=True)
    # 'static' freezes membership at creation; 'dynamic' re-checks the latest
    # import so newly discovered work on the same assets joins automatically.
    project_type  = db.Column(db.String(16), default='static')
    status        = db.Column(db.String(16), default='Open', index=True)
    due_date      = db.Column(db.Date, nullable=True)
    owner_id      = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    closed_at     = db.Column(db.DateTime, nullable=True)
    closed_by_id  = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    source_import_id = db.Column(db.Integer, db.ForeignKey('scan_imports.id'), nullable=True)

    # Criteria a dynamic project re-evaluates against each new import. Without
    # these a dynamic project could only refresh counts on solutions it already
    # held, never absorb newly discovered work, which is the point of it being
    # dynamic. A dynamic project with no criteria keeps the old behaviour rather
    # than silently pulling in the whole estate.
    scope_severities = db.Column(db.String(64), nullable=True)   # 'Critical,High'
    scope_group_id   = db.Column(db.Integer, db.ForeignKey('asset_groups.id'), nullable=True)
    last_refresh_at  = db.Column(db.DateTime, nullable=True)
    last_refresh_added = db.Column(db.Integer, default=0)

    owner       = db.relationship('User', foreign_keys=[owner_id])
    scope_group = db.relationship('AssetGroup', foreign_keys=[scope_group_id])
    created_by = db.relationship('User', foreign_keys=[created_by_id])
    customer   = db.relationship('Customer', foreign_keys=[customer_id])
    items      = db.relationship('RemediationItem', backref='project',
                                 lazy='dynamic', cascade='all, delete-orphan')

    @property
    def severity_list(self):
        return [x for x in (self.scope_severities or '').split(',') if x]

    @property
    def has_scope_criteria(self):
        """Whether this project can absorb newly discovered work."""
        return bool(self.project_type == 'dynamic'
                    and (self.scope_severities or self.scope_group_id))

    @property
    def scope_summary(self):
        if self.project_type != 'dynamic':
            return 'Fixed at creation'
        if not self.has_scope_criteria:
            return 'Dynamic, no criteria set'
        parts = []
        if self.scope_severities:
            parts.append(' / '.join(self.severity_list))
        parts.append(self.scope_group.name if self.scope_group else 'all assets')
        return 'New ' + ' on '.join(parts)

    @property
    def is_expired(self):
        """Past its due date while still open. Derived, never stored."""
        return bool(self.status == 'Open' and self.due_date
                    and self.due_date < datetime.utcnow().date())

    @property
    def display_status(self):
        if self.status == 'Closed':
            return 'Closed'
        return 'Expired' if self.is_expired else 'Open'


class RemediationItem(db.Model):
    """
    One solution within a project: a plugin or package fix, and the hosts it covers.

    Counts are captured at creation so progress can be measured against the
    original scope; live counts are recomputed from the current import when the
    project is viewed.
    """
    __tablename__ = 'remediation_items'
    # Mirrors the InsightVM remediation statuses.
    STATUSES = ('Open', 'Awaiting Verification', 'Will Not Fix', 'Closed')
    DONE     = ('Will Not Fix', 'Closed')

    id            = db.Column(db.Integer, primary_key=True)
    project_id    = db.Column(db.Integer, db.ForeignKey('remediation_projects.id'),
                              nullable=False, index=True)
    plugin_id     = db.Column(db.String(64), index=True)
    plugin_name   = db.Column(db.String(512))
    risk_factor   = db.Column(db.String(20), index=True)
    cvss_score    = db.Column(db.Float, nullable=True)
    solution      = db.Column(db.Text, nullable=True)
    # scope as it stood when the item was added
    host_count    = db.Column(db.Integer, default=0)
    finding_count = db.Column(db.Integer, default=0)

    status        = db.Column(db.String(32), default='Open', index=True)
    assignee_id   = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    notes         = db.Column(db.Text, nullable=True)
    added_at      = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at    = db.Column(db.DateTime, nullable=True)
    updated_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    assignee   = db.relationship('User', foreign_keys=[assignee_id])
    updated_by = db.relationship('User', foreign_keys=[updated_by_id])

    __table_args__ = (db.UniqueConstraint('project_id', 'plugin_id'),)

    @property
    def is_done(self):
        return self.status in self.DONE


class RemediationSnapshot(db.Model):
    """
    Progress for one project as at one scan import.

    Captured lazily the first time a project is viewed after a new import, rather
    than by the importers themselves. That keeps the scanner scripts ignorant of
    projects, and still builds a burn-down history with no scheduled job.
    """
    __tablename__ = 'remediation_snapshots'

    id             = db.Column(db.Integer, primary_key=True)
    project_id     = db.Column(db.Integer, db.ForeignKey('remediation_projects.id'),
                               nullable=False, index=True)
    scan_import_id = db.Column(db.Integer, db.ForeignKey('scan_imports.id'),
                               nullable=True, index=True)
    taken_at       = db.Column(db.DateTime, default=datetime.utcnow)
    report_date    = db.Column(db.Date, nullable=True)

    total_items    = db.Column(db.Integer, default=0)
    done_items     = db.Column(db.Integer, default=0)
    waived_items   = db.Column(db.Integer, default=0)
    verified_items = db.Column(db.Integer, default=0)
    disputed_items = db.Column(db.Integer, default=0)
    open_items     = db.Column(db.Integer, default=0)
    pct            = db.Column(db.Integer, default=0)
    verified_pct   = db.Column(db.Integer, default=0)
    findings_open  = db.Column(db.Integer, default=0)

    project = db.relationship('RemediationProject',
                              backref=db.backref('snapshots', lazy='dynamic',
                                                 cascade='all, delete-orphan'))
    __table_args__ = (db.UniqueConstraint('project_id', 'scan_import_id'),)


class SuppressionRule(db.Model):
    """
    A durable false-positive determination.

    Suppression used to live only as a boolean on each vulnerability row. Because
    every import writes fresh rows, a determination survived exactly until the
    next scan and then silently lapsed. The rule is the record; the row flag is
    just its cached effect, re-applied after each import.

    Scope mirrors RiskAcceptance so the two read the same way:
      plugin  - this detection, wherever it fires (the usual false positive)
      asset   - everything on one host
      finding - one detection on one host
    """
    __tablename__ = 'suppression_rules'
    SCOPES = ('plugin', 'asset', 'finding')

    id            = db.Column(db.Integer, primary_key=True)
    customer_id   = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=True, index=True)
    scope         = db.Column(db.String(16), nullable=False, default='plugin')
    plugin_id     = db.Column(db.String(64), nullable=True, index=True)
    plugin_name   = db.Column(db.String(512), nullable=True)
    asset         = db.Column(db.String(256), nullable=True, index=True)
    reason        = db.Column(db.Text, nullable=False)

    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    review_due    = db.Column(db.DateTime, nullable=True)
    revoked       = db.Column(db.Boolean, default=False, index=True)
    revoked_at    = db.Column(db.DateTime, nullable=True)
    revoked_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    # findings matched at the last application, for display only
    last_applied  = db.Column(db.DateTime, nullable=True)
    match_count   = db.Column(db.Integer, default=0)

    created_by = db.relationship('User', foreign_keys=[created_by_id])
    revoked_by = db.relationship('User', foreign_keys=[revoked_by_id])
    customer   = db.relationship('Customer', foreign_keys=[customer_id])

    @property
    def is_overdue(self):
        return bool(not self.revoked and self.review_due
                    and self.review_due <= datetime.utcnow())

    @property
    def label(self):
        if self.scope == 'asset':
            return f'All findings on {self.asset}'
        if self.scope == 'finding':
            return f'{self.plugin_name or self.plugin_id} on {self.asset}'
        return self.plugin_name or self.plugin_id or 'Unknown detection'
