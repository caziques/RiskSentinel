# Changelog

All notable changes to RiskSentinel (by Beyond Cyber) are documented here.

---

## [4.17.3] - 2026-09-28
### Fixed
- **The software inventory was empty for Cortex-backed customers.** Cortex does not emit CPE. It writes package URLs (`pkg:rpm/redhat/kernel@5.14.0`) and a shorter `app:sshd@8.7p1` form, both of which the CPE parser rejected outright, so the application inventory, the "Applications Detected" column, the applications chart and the `has=apps` filter were all blank for MCR while the page still parsed ~192,000 unusable rows on every load.
- Identifiers are now parsed into one common vendor/product shape whichever scanner produced them. purl namespaces map to the vendor: distro namespaces read as the vendor they are (`redhat` as Red Hat, `rocky` as Rocky Linux), maven groups reduce to their recognisable segment (`io.netty` as Netty), and golang host prefixes are skipped so `github.com/gorilla` reads as Gorilla. An identifier with no namespace gets no vendor rather than being labelled with its package type.
- Where an ecosystem repeats the vendor inside the product, the repeat is dropped: `Netty Netty-Handler` becomes `Netty-Handler`. Vendors shorter than four characters are left alone, since a short match is coincidence rather than repetition. CPE labels are unchanged.
- MCR now shows applications on all 97 assets and a populated application inventory, where it previously showed none.

### Performance
- `_parse_cpe` is cached, and the per-asset loop parses each identifier once rather than four times.
- The inventory's identifier query is now `DISTINCT`. Reading it per finding returned the same asset/identifier pair once per CVE: 191,725 rows to express 2,386 distinct values.
- MCR's inventory page goes from 410ms to roughly 150ms.

---

## [4.17.2] - 2026-09-28
### Fixed
- **The inventory asset fingerprint table was unbounded.** Every asset in the scan was rendered into one table, with the OS, application and search filters applied in the browser over the full row set. 310 assets already produced 422 KB of HTML and it grew linearly with the estate.
- The table is now paged at 100 and the filters moved to the server, because filtering in the browser would otherwise only ever see the rows on the current page and would report a count for the page rather than the estate. Filter state now lives in the URL, so a filtered view can be linked and survives a reload.
- Clicking an OS row, an application row, an application pill, a KPI card or either chart still filters as before; the counts, the active-filter bar and the row highlighting are rendered from the request. Quick search debounces rather than navigating on every keystroke. Pager links carry the active filters, and a page past the end clamps to the last page.
- Inventory HTML for a 310-asset customer drops from 422 KB to 146 KB.

### Known gap
- Cortex populates `cpe` with purl strings (`pkg:rpm/redhat/kernel@...`) rather than CPE, which the CPE parser rejects, so the software and OS inventory is empty for Cortex-backed customers and the page still parses ~192,000 unusable rows on every load. Not addressed here.

---

## [4.17.1] - 2026-09-28
### Fixed
- **The suppression review table was unbounded.** It loaded and rendered every suppressed finding for the customer in one table, the same failure already fixed on the vulnerabilities, plugins and remediation pages. It is now paged at 100 with a pager, and a page number past the end clamps to the last page rather than showing an empty table.
- The three counts at the top are now counted in SQL rather than by materialising the whole set, so the page cost no longer scales with the number of suppressions, and they carry thousand separators.

---

## [4.17.0] - 2026-09-28
### Added
- **Update-API button.** The Update page can now pull straight from the customer's scanner API instead of waiting for the weekly cron or uploading an export. It runs the same importer the cron does, as a subprocess, so a manual update and a scheduled one cannot behave differently.
- The job runs in the background with live output on the page, polled every three seconds. A Cortex pull takes several minutes, which is far longer than a request can be held open, so leaving the page or closing the browser does not stop it.
- Per-customer scanner settings under Admin > Customers: which API backs the customer, which credential file to use, and any options such as `--days 30`. Only the file name is stored. **Secrets never enter the database**; they stay in the `.env` file on the host, and the file list is read from disk so each deployment offers what it actually has.
- A missing credential file is rejected when saving rather than surfacing as a failed job minutes later.
- Configured on this installation: Nebula and Affinity via LevelBlue, MCR via Cortex. Customers with no API configured keep the upload path and say so on the page.

### Changed
- **"Import CSV" in the sidebar is now "Update"**, and the page is "Update Vulnerability Data". Uploading a CSV is one of two ways to update, no longer the only one.
- "Import History" is now "Update History", and its record counts use thousand separators.

---

## [4.16.2] - 2026-09-28
### Fixed
- **git added to the Docker image.** Mounting a git checkout at `/app` was not enough for Admin > Software Update to work in a container: the image had no `git` binary, so the page failed for a second reason after the first was solved.
- Also sets `safe.directory /app`. git refuses to operate on a repository owned by another user, which is exactly how a bind-mounted host checkout appears from inside the container.
- With the checkout mounted, a containerised install can now check for and apply updates from the page. Without the mount, it still correctly reports that an image-baked deployment must be rebuilt on the host.

---

## [4.16.1] - 2026-09-28
### Fixed
- **The update page gave a dead end on containerised installs.** It reported only "This installation is not a git repository, so it cannot self-update", which is true but unhelpful: a container runs code baked into its image, so the remedy is rebuilding the image on the host, not adopting git inside the container.
- The page now detects which deployment it is, via `/.dockerenv`, and shows the right instructions for each.
  - **Container**: the exact host commands to pull, rebuild and recreate, including the volume names, with a warning that changing them silently creates an empty volume rather than failing. Also documents mounting the checkout at `/app` so the button works from then on, turning updates into pull-and-restart.
  - **Bare metal**: the `git-adopt.sh` one-liner.
- Both branches verified by forcing each code path.

---

## [4.16.0] - 2026-09-28
### Added
- **Software Update from git**, at Admin > Software Update. Shows the installed version, branch, commit and remote; checks the repository for waiting changes; lists them with author and message; and applies them on one click.
- The repository is configurable, defaulting to `https://github.com/caziques/RiskSentinel.git`. Changing it repoints the installation, and the current remote is shown so it is never ambiguous which repository an instance follows.
- **Refuses to update over uncommitted local edits.** A dirty working tree blocks the apply button and the route rejects the request, listing the offending files, because a pull would discard that work silently.
- Updates are fast-forward only, so an update can never rewrite local history. If it cannot fast-forward it fails and changes nothing.
- Admin only, enforced on all three routes rather than by hiding the menu entry.
- The page states plainly what an update touches (code, templates, importers, schema via automatic migration) and what it cannot (database, uploads, credentials), since those are excluded from version control.

### Changed
- **Project is now under version control.** `.gitignore` written first and verified before the initial commit: no `.env` file, no database, no uploads, no backups, no scan exports. 59 files committed.
- Excluded two items that were sitting in the project directory but are not part of it: a vendored 57 MB copy of SpiderFoot (2,613 files), and a stray gzip archive named `beyondcyber@10.0.169.10`, evidently a botched `scp` where the filename is the destination host. Both left on disk, simply not tracked.

---

## [4.15.1] - 2026-09-27
### Fixed
- **Severity KPI cards on the Executive Summary did not filter.** Clicking Critical, High, Medium or Low opened the Vulnerabilities page showing every severity. The links passed `risk_factor=` while the route reads `severity=`, so the filter was silently dropped rather than erroring. Five links corrected, including the per-severity links in the SLA breakdown.
- Verified end to end on Nebula and MCR: each card now lands on exactly its own severity, and the record counts match the database precisely (MCR Medium 110,523, Critical 3,797).
- Thousand separator on the Vulnerabilities "records found" count.

---

## [4.15.0] - 2026-09-27
### Added
- **Suppressions now survive the next import.** A false-positive determination is recorded as a durable `SuppressionRule`; the per-row `suppressed` flag is only its cached effect, re-applied after every import. Previously a determination lived solely on the rows of one scan, so it lapsed silently at the next import and the finding quietly reappeared on the Remediation page.
- `apply_suppression_rules()` runs at the end of every USM and Cortex import, and again whenever a rule is created so it takes effect on existing data immediately.
- **Determinations table on the Suppression Review page**: scope, what it applies to, the reason, how many findings it has matched, review date, author, and a Revoke action. Overdue reviews are flagged.
- Revoking a rule reinstates every finding it was suppressing, and the rule stays revoked so the next import does not re-suppress them.
- Reinstating a single finding now also revokes any rule covering it. Without that the flag would be cleared and set again on the next import, which looks like the reinstatement failed.
- Existing row-level suppressions were migrated into rules, so nothing already marked is lost.

### Notes
- Verified by simulating the next weekly scan: 264 matching rows were written unsuppressed, exactly the old failure, and the rule re-suppressed all 264. A revoked rule correctly re-suppressed nothing.
- Rules are per customer. The same detection stays active for other tenants, since a false positive in one environment is not one in another.
- Chosen deliberately over criteria-based filtering at query time: that would have meant rewriting 29 separate `suppressed` filters across the app, with far more risk for the same outcome.

---

## [4.14.0] - 2026-09-27
### Added
- **Suppress a false positive across every affected asset.** The Mark False Positive dialog now asks what the determination applies to: this finding only, or all active findings of the same detection for this customer. The second option shows the exact count before you commit.
- Previously suppression was strictly per row. Marking "Check Point FireWall-1 Identification" as a false positive on one host suppressed 1 of 264 findings, so the plugin stayed on the Remediation page with 263 hosts still attached. That is not what "we do not run Check Point" means.
- Plugin-wide suppression spans all of that customer's imports, so historical views agree, and every affected row records the same reason, author, timestamp and six-month review date.
- Other customers are unaffected: the same detection stays active for them, since a false positive in one environment is not a false positive in another.

### Notes
- Verified on Nebula: suppressing plugin 10044 cleared 791 findings across 88 assets in one action, the detection disappeared from the Remediation page, and all 792 rows appear in the Suppression Review queue for re-review. Default's 267 rows of the same detection were untouched.
- Unchanged limitation, noted previously: suppression is stored per row, so the next import creates fresh unsuppressed rows. Making suppressions match on asset and plugin at query time, the way risk acceptances already work, remains the proper fix.

---

## [4.13.4] - 2026-09-27
### Fixed
- **Plugins and CVEs pages broke on large customers.** Both rendered every row: MCR's Plugins page was **32.8 MB** across 22,566 rows and its CVEs page **40.3 MB** across 22,551, which no browser handles. Affinity's Plugins page was 14.6 MB. Both now render a server-side slice defaulting to the top 250, with a selector for 100 / 250 / 500 / 1,000 / All and a "Showing top N of M" caption, matching the Remediation page. MCR drops to 0.38 MB and 0.47 MB.
- KPIs, charts and severity breakdowns are still computed from the full set; only the table is limited. Choosing All still works but warns first.

### Changed
- Thousand separators on SLA Tracking, CVEs and Plugins: total plugins, critical/high, medium, families, with-CVSS, total CVEs, affected assets, total instances, per-row host and instance counts, and the SLA breached, at-risk, on-track, accepted and overdue figures.
- Plugin IDs, CVSS scores, percentages and years are deliberately left unformatted, as separators there would be wrong.

### Notes
- MCR now reads 191,660 findings, 143,718 breached and 22,565 plugins rather than unpunctuated six-figure strings.
- All twelve pages return 200 for every customer.

---

## [4.13.3] - 2026-09-27
### Fixed
- **Import History on the vulnerability detail page counted findings, not scans.** It listed one row per occurrence, so a CVE affecting many hosts appeared to have been seen in dozens of scans. On MCR, `CVE-2026-47304` showed "52 imports" when that customer has had exactly **one** import; the 52 rows were 39 distinct assets, several carrying the CVE through more than one package, all from the same scan on the same date.
- History is now aggregated per scan import: one row per scan, with earliest first-seen, latest last-seen, worst severity, and counts of affected assets and findings. Verified against every customer, where the number of history rows never exceeds that customer's actual import count.
- The panel also now appears for a single scan instead of being hidden, with a note explaining that a trend builds up as more imports arrive. Previously it required more than one row to show at all, which combined with the per-finding bug meant it appeared when it was wrong and hid when it was right.

### Notes
- This was masked on USM and Rapid7 data, where a CVE typically appears once per import, so the per-finding listing coincidentally resembled a scan history. Cortex records a finding per host and package, which exposed it.

---

## [4.13.2] - 2026-09-27
### Added
- **NIST NVD link on the vulnerability detail page**, shown in the header beside the plugin id and family whenever the identifier is a CVE. This keeps the destination that Executive Summary rows used to open directly, now one click further on rather than lost.

### Fixed
- A "Vulnerability Details" card on that page carried the identifier but was gated behind `not synopsis and not description and not solution and not plugin_output`, so it never rendered for any finding that had a description. Every Cortex finding has one, so the identifier was invisible on all 191,729 MCR rows. The link now lives in the header, which always renders.
- Corrected a claim in the 4.13.1 note above, which stated the detail page already linked to NVD. It did not; I verified after writing it and fixed the page rather than the sentence alone.

### Notes
- Only MCR shows the link, correctly: its `vulnerability_id` holds a real CVE. USM and Rapid7 store a scanner GUID there, so no link is offered for those and the identifier renders as plain text.

---

## [4.13.1] - 2026-09-27
### Changed
- **Priority Vulnerabilities rows on the Executive Summary now open the vulnerability detail page**, matching what clicking a row on the Vulnerabilities page does. Previously they went three different places depending on the row: an external NIST NVD page for CVE-only rows, the plugins page for plugin-named rows, or a vulnerability search otherwise. None of those was the detail page, which is where people expect to land.
- The underlying cause was that `top_vulns` is an aggregate grouped by plugin, so it carried no row id to link to and the template had to guess a destination from the plugin name. The query now also selects `MIN(id)` as a representative row.
- The direct NVD link is preserved by 4.13.2 below, which adds it to the detail page header. (An earlier version of this note claimed the detail page already carried that link; it did not.)
- Verified across all five customers: all ten rows link to a detail page and every link resolves.

---

## [4.13.0] - 2026-09-27
### Fixed
- **USM imports now populate `plugin_family`, and `plugin_id` holds the actual plugin id.** USM packs three values into one `ovalRuleId` field, for example `Windows Windows Explorer Recently Executed Programs 92423`. The importer was storing that entire string as `plugin_id` and leaving `plugin_family` empty, which made the Trends families chart useless for USM customers and weakened plugin-level grouping on the Remediation page.
- The importer now splits it: the trailing number becomes `plugin_id`, and the head with the plugin name removed becomes `plugin_family`. Verified against the live API, the pattern matched 500 of 500 sampled records.
- Records where USM supplies no plugin metadata at all are labelled `Uncategorised` rather than left blank, so the chart is honest instead of showing an unlabelled bar.
- **Backfilled existing USM data**: 8,332 rows gained a real family derived from the stored string, and 5,161 with no metadata were labelled. Nebula now shows General, Windows, Firewalls, Misc., Web Servers, Service detection, Settings, Databases, DNS, SNMP and two Windows sub-families.
- Safe to change: nothing referenced the old `plugin_id` values. Zero risk acceptances and zero remediation-project items pointed at them.

### Added
- The importer's dry run now prints a plugin-family breakdown, so the parsing can be checked before anything is written.

### Notes
- Correction to an earlier note: `plugin_id` was not being truncated. SQLite does not enforce VARCHAR lengths, so the full string was stored. It was simply the wrong value.
- A live dry run against Nebula produced 2,009 findings across twelve families with none uncategorised, so current data parses cleanly.

---

## [4.12.3] - 2026-09-27
### Fixed
- **Cross-tenant data leak on the Trends page.** The plugin-families and recurring-vulnerabilities queries had no customer filter, so they aggregated across every tenant. Every customer's Trends page was showing the largest customer's data: Nebula, Affinity, Europcar and Default all displayed `Server = 190,999`, which is MCR's Cortex estate. Both queries are now scoped to the viewing customer's imports, and each customer's totals reconcile exactly to their own row counts.
- **Cross-tenant leak on the vulnerability detail page.** The "history" panel matched on `vulnerability_id` alone, so where a CVE existed in more than one tenant it listed every tenant's occurrences. Now scoped to the current customer's imports.
- **Cross-tenant leak on the Suppression Review page**, introduced in 4.6.0. It listed suppressed findings across all customers rather than the current one. Now scoped.

### Changed
- Trends built its severity series with five count queries per import. That is now a single grouped query for the whole series; MCR's Trends page went from noticeably slow to 0.18 s.

### Notes
- Audited every `Vulnerability` query in the codebase for missing tenant scoping. The remaining unscoped-looking matches (ports, port detail, family detail, remediation rows) all filter through a `base` list that pins `scan_import_id`, so they were already safe. Three genuine leaks were found and all three are fixed.
- Worth knowing: `plugin_family` is only populated by the Cortex importer. USM and Rapid7 leave it blank, so the families chart shows a single unlabelled bucket for those customers. Cosmetic, but it is why the chart looks bare outside MCR.

---

## [4.12.2] - 2026-09-27
### Changed
- **Query performance on large customers.** MCR's seven main pages took 4.85 s; they now take well under one. Three separate causes, found by profiling rather than guesswork.

- **Composite indexes.** Every hot query filters on `(scan_import_id, suppressed)` then groups, which single-column indexes serve poorly. Added `(scan_import_id, suppressed, risk_factor)`, `(… , asset)`, `(… , vulnerability_id)`, and a covering index carrying the columns the remediation aggregate reads. Measured on 191k rows: severity counts **119ms to 5ms**, distinct assets **25ms to 0ms**, distinct CVEs **55ms to 5ms**, remediation grouping **164ms to 78ms**. Created automatically at startup via a new `INDEX_MIGRATIONS` step, so every deployment picks them up.

- **Column queries instead of ORM entities.** The SLA page built 191,729 fully-populated `Vulnerability` objects to read eight fields, costing about 2.9 s in SQLAlchemy against 122 ms of actual SQL. The SLA page, its CSV export and the executive summary now select just the columns they use. Executive **1.69s to 0.58s**.

- **Age trend aggregated in SQL.** The biggest single cost on the SLA page: for each of twelve imports, for each of four severities, it loaded every matching finding as an ORM object purely to average a date difference. Now one grouped query per import using `julianday()`. SLA **2.23s to 0.98s**.
  - The per-row difference is cast to an integer before averaging, matching Python's `timedelta.days` truncation. Averaging raw fractions instead shifted some figures by a day. Verified identical across all five customers.

### Notes
- Database grows 144 MB to 191 MB for the indexes. Bulk insert still runs at roughly 74,000 rows per second, so a full 191,729-row Cortex import writes in about three seconds; the added index maintenance is not material.
- `ix_vuln_import_supp_plugin` was trialled and dropped: it made the remediation aggregate slightly worse, because that query reads columns the index does not carry. The covering index replaced it.
- MCR remains the slowest customer simply because it holds 191,729 of the 229,801 rows. Remaining time is Python building the display rows, not the database.

---

## [4.12.1] - 2026-09-27
### Changed
- **SQLite now runs in WAL mode.** The default rollback journal gives a writer an exclusive lock, so a bulk import stalled every reader. Measured on the real database: a simple count during a bulk write took **1,043 ms before, 6 ms after**. This matters because imports run on a cron while people are using the portal.
- Pragmas applied on every connection: `journal_mode=WAL`, `synchronous=NORMAL` (the safe pairing with WAL), `busy_timeout=15000` so contention waits instead of failing, `cache_size=-64000` raising the page cache from 2 MB to 64 MB, and `temp_store=MEMORY`.
- Foreign-key enforcement deliberately left off. Turning it on would be a behaviour change rather than a concurrency fix, and belongs in its own piece of work.

### Fixed
- `restore.sh` now deletes the `-wal` and `-shm` sidecar files before restoring the database. Under WAL, leaving a stale WAL beside a restored file lets SQLite replay old transactions over it. `backup.sh` needed no change as it already uses the WAL-safe `sqlite3 .backup` API.
- `.gitignore` covers the WAL sidecar files.

### Notes
- No schema change, no migration, no downtime. `journal_mode` persists in the database file; the remaining pragmas are per-connection.
- Current scale for reference: 144 MB, 229,801 vulnerability rows, worst aggregate query 145 ms. Size is nowhere near a reason to leave SQLite. The real trigger for a move to MySQL would be wanting a second application instance, since SQLite is a file and cannot be shared between hosts.
- The Mac Mini deployment and the Affinity standalone package still need the same change.

---

## [4.12.0] - 2026-09-27
### Added
- **Close on scanner verification.** When solutions in a project are no longer detected by the latest scan but are still marked outstanding, the project shows a prompt with a one-click action to close them all. Each closure records who did it and appends a note naming the scan that verified it.
  - Deliberately prompted rather than automatic: absence from a single scan is strong evidence but not proof, and closing a finding is a decision someone should own.
- **Progress history and burn-down chart.** New `RemediationSnapshot` table records each project's progress against each scan import, and the project page plots resolved-by-owner percentage, scanner-verified percentage, and findings still open on a dual-axis chart.
  - Snapshots are captured lazily when a project is viewed after a new import, not by the importers. The scanner scripts stay unaware of projects, no scheduled job is needed, and history accumulates on its own.
  - Unique on (project, import) so repeat views update rather than duplicate, and status changes made later in the same scan cycle are still captured.
  - With one scan the page explains that a trend appears after the next import, rather than showing an empty chart.

### Notes
- Verified: a project scoped against an older import showed 4 of 8 solutions already scanner-verified with no human action, purely because those solutions disappeared in a later scan. Closing them recorded the verifying scan in each item's notes.
- Still outstanding from the earlier review: dynamic projects refresh host counts for solutions already in scope but do not absorb newly discovered solutions, because no scope criteria are stored. Static and dynamic therefore differ less than the labels imply.

---

## [4.11.1] - 2026-09-27
### Fixed
- **Remediation page broke on large estates.** MCR has 22,558 distinct solutions and every one was rendered into the table, producing a 53 MB page that hung the browser. DataTables paginates client-side, so the whole set had to reach the DOM before any paging happened. Affinity was affected too at 22 MB.
- The table now renders a server-side slice, defaulting to the top 250, with a selector for 100 / 250 / 500 / 1,000 / All and a "Showing top N of M" caption. MCR drops from 53 MB to 0.66 MB and every customer now loads in under half a second.
- Choosing All still works but carries a warning, since the ranking means the top few hundred solutions account for nearly all the risk.
- All KPIs, percentages, solution groupings and severity counts are still computed across the **full** set, so nothing downstream of the limit changes.
- The risk-versus-hosts bubble chart is capped at 400 points. It was plotting every solution, which was both unreadable and megabytes of JSON.

### Changed
- Thousand separators on the Remediation page: total solutions, SLA breaches, Critical/High count, informational count, total risk, and the per-row host, finding, risk-score and age columns. Percentages, CVSS scores and rank are deliberately left unformatted.

---

## [4.11.0] - 2026-09-27
### Added
- **Remediation Projects** — time-boxed bundles of work grouped by solution, owned and tracked to completion. Modelled on the InsightVM remediation-workflow concept but scanner-agnostic, so it works across USM, Rapid7 and Cortex alike.
- `RemediationProject` and `RemediationItem` models (new tables, created automatically on startup).
- **Projects page** (`/projects`) — card grid with progress bars, filters for All / Open / Closed, owner, due date, and badges for expired and disputed projects.
- **Project detail page** — KPI cards, a solutions table with inline status and assignee dropdowns, and per-item removal.
- **Solution statuses** mirroring InsightVM: Open, Awaiting Verification, Will Not Fix, Closed. Project status is Open or Closed, with **Expired derived** from the due date rather than stored, so it is always accurate without a scheduled job.
- **Static and dynamic scoping.** Static freezes membership at creation; dynamic re-checks the latest import on view and absorbs newly discovered hosts for solutions already in scope.
- **Two independent progress measures.** *Solutions Resolved* counts what an owner has closed or waived. *Scanner Verified* counts solutions no longer present in the latest scan. Where an item is marked Closed but the scanner still detects it, the project is flagged **disputed** with a banner, which surfaces fixes that did not take or were never rescanned.
- **Bulk add from the Remediation page** — checkbox column plus an action bar to push selected solutions into any open project, or jump to project creation.
- **Per-project CSV export** including live "findings still present" counts alongside the scoped figures.
- Admin-only project deletion; items cascade so no orphans are left behind.
- Sidebar entry under Overview.

### Notes
- Work is grouped by solution rather than by finding, because one package upgrade typically clears many CVEs across many hosts, and that is the unit a remediation team actions.
- Risk Acceptance and Will Not Fix stay separate on purpose: Risk Acceptance carries formal approval and a 90 day expiry per NBL-IT-020, while Will Not Fix is a working decision inside a project.

---

## [4.10.1] - 2026-09-26
### Changed
- **Thousand separators across the Executive Summary.** Six-figure counts were rendering unpunctuated (191729), which is hard to read at a glance and easy to misread by an order of magnitude.
- Animated KPI counters now format through `toLocaleString`, so separators appear during the count-up as well as at rest, and decimal places are preserved (average CVSS still shows one).
- Server-rendered figures formatted too: accepted-risk and excluded-finding badges, the new-findings delta, asset counts, the affected-asset column in Priority Vulnerabilities, and every auto-generated Key Findings bullet.
- Chart.js axis labels group thousands via a global tick formatter, covering the trend and top-assets charts.

---

## [4.10.0] - 2026-09-25
### Added
- **Findings / CVEs toggle on the Executive Summary.** Scanner consoles headline distinct CVEs while RiskSentinel counts findings, so the same estate reads as two very different numbers and the difference looked like a data error. Both are now visible on one page.
  - **Findings** (default): one per affected host and package, which is the remediation workload and what SLA ageing is measured against.
  - **CVEs**: one per distinct CVE, rated by its worst instance across the estate, which is how the Cortex and Tenable consoles present the same data.
  - A caption always shows both totals, so the relationship is visible without switching.
  - The toggle carries the selected import and the exclude-accepted state through, in both directions.
- Stored data is unchanged; this is a presentation choice only. Severity remains per finding, because one Critical on fifty hosts is fifty jobs with fifty separate SLA clocks.

### Notes
- For MCR the two views read 191,729 findings against 22,565 CVEs, and 3,797 Critical findings against 832 Critical CVEs. Both describe the same estate.
- Counting CVEs by worst instance gives 6,162 Critical and High against the Cortex console's 5,959. The roughly 200 difference is a methodology difference, not missing data: Cortex labels a CVE from its CVSS score, while this view takes the worst severity Cortex assigned to any instance of it. Every CVE in the console export is present in the import, and finding counts reconcile to 0.02%.

---

## [4.9.1] - 2026-09-25
### Fixed
- **Cortex importer was reading the wrong dataset and has been rebuilt.** The 4.9.0 import was discarded (57,901 records deleted) and replaced with 191,729 findings that reconcile exactly to the Cortex console.
- Root cause: on new-platform Cortex tenants the legacy Cortex XDR datasets `va_cves` and `va_endpoints` still exist and still return internally consistent, freshly-calculated data, but they do not reflect what the console reports. They understated the estate by roughly 70% and attributed findings to hosts the console shows as clean. Caught because a host the console reported as having zero vulnerabilities appeared in our data with 643.
- The importer now reads `dataset = findings` filtered to `xdm.finding.category = "VULNERABILITY"` and `is_active = true`, which is the model the console renders. Verified against a console CSV export: all 96 shared assets match exactly, count for count.
- Richer fields now captured that the legacy path did not expose: EPSS score, exploitability, whether a fix exists, fix versions, package purl, and OS distribution.
- The importer prints the Cortex-reported total before fetching and warns if the retrieved count drifts more than 1%, so a silent truncation cannot pass unnoticed again.

### Changed
- **Fetch strategy rewritten for speed.** Paging the full result set was quadratic: every page made Cortex re-scan and re-sort all 191,729 findings to return 1,000 rows, taking about 76 minutes. Work is now partitioned by asset (97 partitions, each sorting only its own rows) and run across 3 concurrent workers, cutting the run to a few minutes. Cortex offers no bulk results-stream on this tenant, so paging cannot be avoided entirely.
- Cortex rejects excess concurrent XQL queries with a 500 carrying "parallel running queries". That is back-pressure, not failure, and is now retried with exponential backoff rather than aborting the import. Timeouts and 429s are handled the same way.
- SLA seeding: `xdm.finding.first_observed` is frequently null, so new findings fall back to the CVE publish date and then last-observed. Existing `first_seen` values are carried forward per asset and CVE across runs so ageing stays honest.

---

## [4.9.0] - 2026-09-25
### Added
- **Palo Alto Cortex XDR importer** (`cortex_import.py`), the third scanner integration alongside USM and Rapid7. Pulls Host Insights vulnerability assessment data and writes it to the same `Vulnerability` model, so every existing page, SLA calculation and risk acceptance works on it unchanged.
- New customer **MCR**, Cortex tenant `api-mcr.xdr.eu.paloaltonetworks.com`, credentials in `.env.cortex.mcr` (mode 600).
- Initial MCR import: 57,901 findings across 156 hosts from 4,124 distinct CVEs. 2,869 Critical, 42,604 High, 12,286 Medium, 142 Low.
- Supports `--dry-run`, `--days`, `--customer` and `--env-file`, matching the USM importer's interface.

### Notes on the Cortex integration
- Cortex exposes vulnerability data **only** through XQL against the `va_cves` dataset. Every REST path for Host Insights returns 500, so there is no alternative route.
- `va_cves` carries severity, CVSS base score, description, affected products and the affected host list, so findings are produced by exploding CVE x host. No external CVE enrichment is needed.
- The XQL API caps result pages at 1,000 rows and reports that cap as the total rather than signalling truncation. The importer uses keyset pagination on `cve_id`, deduplicating overlapping pages; verified to land exactly on the server-side aggregate of 4,124 CVEs and 57,901 findings.
- The endpoints API rejects any page larger than 100, so asset metadata is fetched 100 at a time.
- **SLA clock handling.** Cortex has no per-host first-detected timestamp: `modification_date` is the last assessment time and is rewritten on every scan, so using it would reset ageing to zero on each import, and `publication_date` is when the CVE went public rather than when it was found. New findings are therefore seeded with the later of the CVE publication date and the agent's install date, which is the earliest the finding could plausibly have existed on that host. Subsequent imports carry the original `first_seen` forward per asset and CVE so ageing and breach counts stay honest.

### Tenant findings worth acting on
- The Cortex API key needed the Viewer role and SBAC disabled before endpoint data was reachable.
- 194 of 233 hosts in `host_inventory` carry an empty vulnerability report, so only about 17% of the estate reports VA data. Worth confirming Host Insights is enabled estate-wide.
- 74% of MCR findings are High severity, which will produce a very large SLA breach count against the 30 day internal target.

---

## [4.8.1] - 2026-09-14
### Fixed
- **Changelog page was silently dropping releases.** The `/changelog` parser matched only an em-dash between the version and the date, so entries written with a plain hyphen never rendered. Versions 4.6.0, 4.7.0, 4.7.1 and 4.8.0 were all missing from the page. The parser now accepts either separator.

---

## [4.8.0] - 2026-09-11
### Added
- **Multi-tenant USM support in `levelblue_import.py`.** Each USM Anywhere instance now has its own credentials file, selected with `--env-file`. Without the flag the default `.env.levelblue` still applies, so existing Nebula imports are unchanged.
- `--sources` argument (comma separated, default `tenabletvsapp`). Tenants differ in which scanner feeds USM, so the source filter is no longer hardcoded.
- `--dry-run` argument, matching the single-tenant importer: fetches and summarises without writing to the database.
- New customer **Affinity** (Affinity Health), USM tenant `affinity.alienvault.cloud`, credentials in `.env.levelblue.affinity` (mode 600).
- Initial Affinity import: 9,885 findings over a 30 day window from Tenable plus SentinelOne. 1,449 Critical, 4,203 High, 3,455 Medium, 290 Low, 488 Informational.

### Fixed
- Imported findings recorded `source` as the literal string `tenabletvsapp` regardless of origin. The actual source from the USM record is now stored, so SentinelOne findings are no longer mislabelled as Tenable.

### Notes
- Affinity is predominantly a SentinelOne deployment: 16,406 valid SentinelOne records against 57 valid Tenable records. Importing with the Nebula defaults would have yielded 57 findings, 55 of them Informational.
- Affinity's Tenable integration flags 1,377 of 1,434 records invalid (96%), worth investigating on the Affinity side.
- A 30 day window suits SentinelOne data, whose findings have a median age of 9.3 days and persist until patched. The 7 day default would capture under half.

---

## [4.7.1] - 2026-09-11
### Changed
- **Executive Summary now defaults to excluding accepted risk.** The executive view is the reported position and accepted risk is formally signed off, so it no longer inflates the headline numbers by default. The switch still turns it off for a full unfiltered view.
- `_navUrl()` in `executive.html` now always sends `exclude_accepted` explicitly rather than omitting it when off. Without this the new server-side default would have turned the switch back on as soon as it was cleared, making the toggle one-way.
- Vulnerabilities, SLA / Age Tracking and the breached CSV export are unchanged and still default to including accepted risk.

---

## [4.7.0] - 2026-09-08
### Added
- **Internet-facing SLA tier** (NBL-IT-020 section 11) - assets in an asset group named `Internet-Facing` are measured against Critical 48 hours, High 15 days, Medium 30 days and Low 90 days, instead of the internal 7/30/90/180
- Exposure is driven by asset group membership, so the tier is maintained through the existing Asset Groups screen with no new mechanism
- `_internet_facing_assets()` and `_sla_for()` helpers; tier applied on SLA tracking, the breached CSV export, the executive summary and the remediation engine
- Remediation rows use the stricter tier when any affected asset is internet-facing, so a plugin is not reported compliant while an exposed host is outstanding
- SLA page shows both tiers in the targets panel and a globe marker against internet-facing findings; the compliance table shows the shorter target where exposed findings exist
- Breached CSV export gains an `Exposure` column
- **Exclude Accepted Risk toggle on the SLA / Age Tracking page**, matching the Executive Summary and Vulnerabilities pages; the toggle state carries through to the CSV export

### Changed
- SLA page shows a prompt when no assets are tagged internet-facing yet, explaining how to enable the tier

---

## [4.6.0] - 2026-09-08
### Added
- **Suppression Review page** (`/suppressions`) - queue of all false positive determinations, ordered by review date, with counts for overdue and undated suppressions (NBL-IT-020 section 14)
- **Mark False Positive** action on the vulnerability detail page - captures a mandatory written basis, records who suppressed it and when, and sets a review date six months out
- Suppressed findings show an inline banner on the detail page with the reason, date and review status, plus a Reinstate action
- `suppression_reason`, `suppressed_at`, `suppressed_by_id` and `suppression_review_due` columns added to `vulnerabilities` (auto-migrated)
- Critical and High findings require analyst or admin role before they can be suppressed

### Changed
- **Risk acceptance expiry is now mandatory and capped at 90 days** per NBL-IT-020 section 19.2; the date picker enforces the range and the server validates it, rejecting blank, past and over-cap dates
- SLA ageing bands changed to 0 to 7, 8 to 30, 31 to 60, 61 to 90 and over 90 days to match NBL-IT-020 section 18 (previously 0-7, 8-30, 31-90, 91-180, 180+)
- Ageing band labels no longer use en-dashes

### Fixed
- **Risk acceptance tag collision across customers** - `_next_ra_tag()` scoped its lookup to the current customer while `tag` carries a global unique constraint, so the first acceptance recorded by a second customer failed with an IntegrityError. The sequence is now global and computed numerically so it survives past RA-YYYY-999.

---

## [4.5.0] — 2026-07-09
### Added
- **Export Breached CSV button on SLA / Age Tracking page** — downloads all SLA-breached findings as a CSV
- Columns: Status, Asset, IP Address, Plugin, Severity, CVSS, First Seen, Age (days), SLA (days), Overdue by
- Sorted by most overdue first; filename auto-built as `SLA-Breached-<Customer>-<date>.csv`
- Respects the active import selector; button sits alongside the existing PDF export button

---

## [4.4.0] — 2026-06-14
### Added
- **Export PDF button on the SLA / Age Tracking page** — downloads the full page (KPIs, charts, and findings table) as a multi-page A4 PDF
- Client-side generation via html2canvas + jsPDF (no server-side dependency); captures the live dark-themed page including Chart.js canvases
- Filename auto-built as `SLA-<Customer>-<report-date>.pdf`
- Page selector + button hidden during capture; print `@media` stylesheet added as a fallback for Ctrl+P
- Verified end-to-end in-browser: captures the report and produces a 6-page PDF with no console errors

---

## [4.3.0] — 2026-06-11
### Changed
- **Login screen overhaul — phoenix edition** 🔥
- Hand-drawn SVG phoenix hovers above the login card: flapping wings, swaying tail streamers, flickering crest, glowing core, flame shimmer
- Full-screen canvas particle system: embers shed continuously from the phoenix tail/wingtips plus ambient embers drifting up from the bottom of the screen (additive blending for real fire glow)
- **Burning-day rebirth cycle** every ~21s — the phoenix combusts in a 160-particle burst with a screen flash, collapses to ash, then rises again with a golden flare (proper Fawkes behaviour)
- Sign In button restyled with an animated fire gradient; submitting triggers a combustion flare
- Login card gets a breathing ember glow, blur backdrop, and fire-orange input focus rings
- All animation honours `prefers-reduced-motion` (static page, canvas hidden)
- Version bumped to `4.3.0`

---

## [4.2.0] — 2026-06-11
### Changed
- **Executive Summary visual overhaul** — animated, dynamic presentation throughout
- Risk Grade now renders as an SVG progress ring that draws itself to the score with a colour-matched glow; grade letter pops in after the ring completes
- All KPI numbers count up from 0 with ease-out timing (Avg CVSS animates with one decimal)
- Cards stagger-reveal on scroll via IntersectionObserver; hover lifts cards with glow and a sheen sweep
- Critical KPI card pulses red and shows a flickering 🔥 when criticals exist
- SLA donut gains an animated centre label showing compliance % counting up
- Risk Trend chart: gradient area fills under Critical/High lines, per-point staggered draw animation
- Top Exposed Assets bars grow in with per-row stagger and rounded corners
- Priority Vulnerabilities table: inline CVSS mini-meters that fill to score
- Key Findings bullets slide in one-by-one with severity-coloured accents and hover highlight
- Animated score bar with shimmer; live pulse dot next to scan name in header
- All animations respect `prefers-reduced-motion` and are disabled for print
- Version bumped to `4.2.0`

---

## [4.1.0] — 2026-06-11
### Changed
- **User Management page is now fully dynamic** — no page reloads for any action
- User table rendered client-side from new `GET /api/admin/users` JSON endpoint
- Create user, change role, toggle active, reset password, assign/remove customer all happen via AJAX with toast notifications
- Customer assignment now uses an inline dropdown (+) per user row instead of a modal
- Live search box (filters by username, email, or customer name) and role filter dropdown
- Password visibility toggle on the create-user form
- Customer Access picker auto-hides when creating an admin (admins see all customers)
- All admin user/customer routes return JSON when called via `fetch` (`X-Requested-With: fetch`), still fall back to flash+redirect for plain form posts
- Version bumped to `4.1.0`

---

## [4.0.1] — 2026-05-12
### Fixed
- User Management page now shows customer assignments per user inline in the user table
- Add New User form includes a customer checkbox list — assign one or more customers at creation time
- `+` button on each user row opens an "Assign Customer" modal listing only unassigned customers
- × button on each customer badge removes the user from that customer immediately
- `User` model gains a direct `customers` many-to-many relationship (viewonly, via `user_customers`)
- `admin_add_user` route now accepts `customer_ids[]` and creates `UserCustomer` records on user creation

---

## [4.0.0] — 2026-05-12
### Added
- **Multi-tenant support** — all data is now scoped to a Customer
- `Customer` model — create/rename/activate/deactivate via Admin → Customers
- `UserCustomer` join table — assign users to one or more customers (admins see all)
- Customer chooser at login — auto-selects if only one customer, shows picker for multiple
- Switch customer button in sidebar footer (shown when user has access to multiple)
- `--customer` argument on `levelblue_import.py` and `rapid7_import.py` (defaults to `Default`)
- Migration: existing imports, risk acceptances, and asset groups back-filled to `Default` customer

### Changed
- Version bumped to `4.0.0`
- All data queries (`ScanImport`, `RiskAcceptance`, `AssetGroup`) now customer-scoped via `_cust_scan_q()`, `_cust_ra_q()`, `_cust_ag_q()` helpers
- Login redirects to customer chooser instead of directly to dashboard

---

## [3.2.0] — 2026-04-30
### Added
- `rapid7_fetch.py` — fetches vulnerability findings from Rapid7 InsightVM Cloud and writes a CSV report
- `rapid7_import.py` — fetches findings directly into the vuln-portal SQLite database (same pattern as `levelblue_import.py`)
- `.env.rapid7` — credential template (`RAPID7_API_KEY`, `RAPID7_REGION`)
- Uses Rapid7 Bulk Export GraphQL API (`POST /export/graphql`) — triggers async Parquet export, polls until `SUCCEEDED`, downloads `asset` + `asset_vulnerability` Parquet files
- Produces 3,257 findings across 333 assets (905 Critical, 1,941 High, 411 Medium)
- `pyarrow>=14.0` added to `requirements.txt`
- `RAPID7_API_KEY` and `RAPID7_REGION` wired into `docker-compose.prod.yml`

---

## [3.1.0] — 2026-04-28
### Added
- `levelblue_import.py` — automated importer that fetches vulnerabilities directly from the LevelBlue / AlienVault USM API and writes them into the database without a CSV upload
- Filters to match the USM "Investigate" view: `source=tenabletvsapp`, `valid=true`, `suppressed=No`, last 7 days
- `requests>=2.31` added to `requirements.txt` (required by importer)
- LevelBlue credentials (`LEVELBLUE_CLIENT_ID`, `LEVELBLUE_CLIENT_SECRET`, `LEVELBLUE_BASE_URL`) wired into `docker-compose.prod.yml`
- Weekly cron job (`0 6 * * 1`) via `docker exec` for production deployment
- `backup.sh` — hot backup of SQLite DB + uploads while container is live, retains 10 most recent
- `restore.sh` — stops container, restores DB + uploads from tarball, restarts container

---

## [3.0.0] — 2026-04-09
### Added
- Asset Groups: create named groups, assign a colour, and add/remove assets via a multi-select picker with live filter
- Assets can belong to multiple groups simultaneously (many-to-many)
- Group badges shown on Assets list page (linked to group detail) and on Asset Detail header
- Asset Groups page (`/asset-groups`) — card grid with member count, description, quick "Accept Risk" shortcut
- Asset Group Detail page (`/asset-groups/<id>`) — manage members, edit group info, delete (admin only)
- Risk Acceptance: new **Group** scope — accepts risk for every asset currently in the selected group
- `AssetGroup` and `AssetGroupMember` models added to database
- `group_id` FK added to `RiskAcceptance` — group scope entries link back to group and display group name in register
- Sidebar: Asset Groups link added under Overview section

---

## [2.9.0] — 2026-03-28
### Added
- Vulnerabilities list: CVE IDs now render as inline NIST NVD external links (↗ icon) in the name column
- Asset detail: same NIST link treatment on all vulnerability rows
- Both pages apply `plugin_name → plugin_id → vulnerability_id → —` fallback for display name

---

## [2.9.0] — 2026-03-31
### Added
- `nginx.conf` — reverse proxy with HTTP→HTTPS redirect, TLS 1.2/1.3, rate-limiting on `/login`, 50 MB upload limit, security headers
- `docker-compose.prod.yml` — production compose using pre-built image + nginx sidecar
- `.env.example` — template for production environment variables

---

## [2.8.0] — 2026-03-28
### Fixed
- Asset detail page: vulnerability name column now falls back to `plugin_id` → `vulnerability_id` → `—` when `plugin_name` is empty (consistent with other pages)

---

## [2.7.0] — 2026-03-28
### Added
- Risk Acceptance: admin-only permanent delete button (trash icon) shown next to the revoke button for each entry
- `POST /risk-acceptance/<id>/delete` route — 403 for non-admins, permanently removes the DB record

---

## [2.6.0] — 2026-03-28
### Fixed
- Executive Summary "Exclude Accepted" toggle now correctly filters assets when `scope='finding'` with no `plugin_id` — these are now treated as whole-asset exclusions (added to `excl_assets`) rather than silently skipped
- Added missing `and_` import from sqlalchemy (prevented finding-scope exclusions with a plugin_id from working)

---

## [2.5.0] — 2026-03-28
### Changed
- Executive Summary "Exclude Accepted" toggle now filters ALL data including the Risk Trend chart (every historical data point recalculated excluding accepted assets/findings)
- Refactored RA exclusion logic: `_fetch_active_ras()`, `_ra_criteria()`, `_apply_ra_filter()` helpers replace the ID-set approach — more efficient (criteria-based SQL vs large NOT IN list)
- Trend chart exclusion uses the same asset/plugin criteria applied directly per-import per-severity query

---

## [2.4.0] — 2026-03-28
### Added
- Executive Summary: "Exclude Accepted" toggle switch in top-right header (left of import selector)
- Toggle reloads page with `?exclude_accepted=1`, removing accepted-risk findings from all KPIs, severity counts, SLA stats, risk grade, top assets, and priority vulnerabilities
- Badge shows total active acceptance count; secondary badge shows how many findings are hidden when toggle is on
- Key findings bullet added when exclusion is active ("N findings excluded — covered by accepted risk")
- Fixed import selector on Executive Summary (was always showing latest; now respects `?import_id=` param)
- `_accepted_vuln_ids()` helper in app.py returns the set of Vulnerability IDs covered by active (non-revoked, non-expired) acceptances

---

## [2.3.0] — 2026-03-27
### Changed
- Favicon updated to match www.beyondcyber.co.za (downloaded from site, replaces SVG placeholder)

---

## [2.2.0] — 2026-03-27
### Added
- Risk Acceptance Register (`/risk-acceptance`) — record accepted risks with auto-generated `RA-YYYY-NNN` tags
- `RiskAcceptance` model: scope (Asset / Finding), asset, plugin, CVE ID, reason, expiry date, notes, revoke support
- KPI cards: Total, Active, Expiring Soon (<30 days), Expired, Revoked with client-side filter
- "Accept Risk" button on Vulnerability Detail page (pre-fills modal with plugin + asset)
- "Accept Whole Asset" button on Asset Detail page (pre-fills asset scope)
- `/api/risk-acceptance/tags` endpoint for programmatic lookups
- Sidebar nav link under Overview section

---

## [2.1.0] — 2026-03-27
### Changed
- Default landing page after login is now Executive Summary (previously Dashboard)

---

## [2.0.0] — 2026-03-27
### Fixed
- Login screen now displays the `logo_main.svg` logo instead of the old Bootstrap shield icon

---

## [1.9.0] — 2026-03-27
### Fixed
- Remediation screen now falls back to `plugin_id` when `plugin_name` is null, so all vulnerability rows display a meaningful name

---

## [1.8.0] — 2026-03-27
### Changed
- Removed Dashboard link from sidebar navigation

---

## [1.7.0] — 2026-03-27
### Added
- Clicking the asset count badge on Priority Vulnerabilities opens a modal listing all affected assets (name, IP, port, first/last seen) — fetched via new `/api/vuln-assets` endpoint
- Asset names in the modal link through to the Asset Detail page

---

## [1.6.0] — 2026-03-27
### Fixed
- Priority Vulnerabilities table on Executive Summary showed blank names for CVE-based findings — `vulnerability_id` added to query and used as fallback when `plugin_name` is empty
- CVE rows in Priority Vulnerabilities now open NIST NVD (`nvd.nist.gov/vuln/detail/CVE-...`) in a new tab when clicked
- Plugin-named rows still navigate to the plugins page; other non-CVE rows fall back to vulnerability search
- Key findings bullet also uses `vulnerability_id` fallback for most prevalent risk sentence

---

## [1.5.0] — 2026-03-27
### Changed
- Analysis sidebar section collapsed into a Bootstrap collapsible dropdown (9 items → 1 toggle)
- Dropdown auto-expands when navigating to any Analysis page; chevron rotates on open/close
- Removed Changelog link from sidebar (route still accessible at `/changelog`)

### Added
- `CHANGELOG.md` set as the authoritative change record — updated after every change

---

## [1.4.0] — 2026-03-27
### Added
- Threat Intelligence News page (`/news`) — fetches RSS/Atom feeds, displays articles sorted by date with per-feed filter pills
- Admin News Feeds manager (`/admin/feeds`) — add, enable/disable, delete, and force-refresh feeds
- Default feed seeded: Unit 42 — Palo Alto Networks (`https://unit42.paloaltonetworks.com/feed/`)
- `NewsFeed` model added to database (`news_feeds` table)
- `feedparser>=6.0` added to `requirements.txt`
- 30-minute in-memory feed cache with per-feed invalidation
- News Feeds link added under Admin section in sidebar

### Fixed
- Severity Distribution donut on Executive Summary rendering disproportionately large — constrained to 260px max-width with `aspectRatio: 1`
- Plugin names blank for CVE-based vulnerabilities — column now falls back to `vulnerability_id` when `plugin_name` is empty; column renamed "Vulnerability / Plugin"
- `TypeError: 'builtin_function_or_method' object is not iterable` on Changelog page — dict key `items` conflicted with Python's `dict.items()` method; renamed to `entries`

---

## [1.3.0] — 2026-03-27
### Changed
- Application renamed from VulnPortal to RiskSentinel
- Website title and favicon updated to "Beyond Cyber"
- Sidebar logo and brand name link to `https://www.beyondcyber.co.za`
- Docker service and container renamed from `vuln-portal` to `risk-sentinel`

### Added
- Version constant `__version__` in `app.py` (single source of truth)
- `@app.context_processor` injects `app_version` into all templates
- `/changelog` route parses `CHANGELOG.md` into structured release entries
- `changelog.html` template with colour-coded Added/Changed/Fixed/Removed badges

---

## [1.2.0] — 2026-03-27
### Added
- Executive Summary page with interactive KPI cards, risk grade, SLA compliance gauge, top assets chart, and auto-generated key findings
- NIST NVD hyperlinks on CVE IDs (opens `nvd.nist.gov` in new tab)
- Docker container support with `Dockerfile`, `docker-compose.yml`, and `entrypoint.sh`
- `gunicorn>=21.2` added to `requirements.txt` for production serving

### Changed
- Severity label "None" renamed to "Informational" across all views

---

## [1.1.0] — 2026-03-27
### Added
- Asset Inventory & Fingerprinting page — OS detection, CPE parsing, software version tracking, week-over-week change badges; fully interactive with client-side filtering
- CVE Extraction & Analysis page — top CVEs by host count, CVSS distribution, year breakdown, CVE detail drill-down with affected hosts and scan history
- Age / SLA Tracking page — SLA compliance by severity, age distribution chart, breached/at-risk/on-track status, per-finding DataTable
- Custom Beyond Cyber logo in sidebar (replaces default shield icon)

### Fixed
- SyntaxError in inventory CPE helper (`_humanise` call inside set comprehension)

---

## [1.0.0] — 2026-03-26
### Added
- Interactive Dashboard rewrite — clickable KPI cards, Bootstrap Offcanvas drill-down drawer (AJAX), delta badges (new/resolved), clickable severity donut, weekly trend chart, stacked asset bar chart, import rows
- `/api/dashboard/vulns` AJAX endpoint for drawer filtering
- Dashboard import selector dropdown
- Base navigation: Executive Summary, Dashboard, Trends, Remediation, SLA Tracking, Vulnerabilities, CVEs, Assets, Inventory, Plugins, Open Ports, Search, Import CSV, Admin Users

---

## [0.1.0] — 2026-03-25
### Added
- Initial project scaffold: Flask + SQLAlchemy + Flask-Login
- SQLite database with `User`, `ScanImport`, `Vulnerability` models
- CSV import pipeline (Tenable format)
- Core pages: Dashboard, Vulnerabilities, Assets, Asset Detail, Vulnerability Detail, Plugins, Plugin Detail, Ports, Port Detail, Trends, Remediation, Search
- Bootstrap 5 dark theme, Chart.js, DataTables
- Role-based access (admin / analyst / viewer)
- `setup.sh` for local development
