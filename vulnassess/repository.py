"""Backend assessment repository: SQLite fallback or Supabase PostgreSQL.

The connection is chosen from a single backend-only value:

* ``path/to.sqlite``            -> local SQLite fallback (also read-write)
* ``postgresql://...`` URL      -> Supabase/PostgreSQL backend
* ``env:VULNASS_DATABASE_URL``  -> the URL above, read from the environment

Credentials never reach the browser: the UI server only calls the read methods
below through its GET routes, and the PostgreSQL connection is opened with
``SET TRANSACTION READ ONLY``.

All queries are parameterised. JSON payloads are stored as JSON text in SQLite
and jsonb in PostgreSQL.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from vulnassess.errors import ConfigError

ENV_VAR = "VULNASS_DATABASE_URL"

# SQLite mirror of migrations 001-009 for the local fallback backend. The
# PostgreSQL schema lives in db/migrations/*.sql; keep the two aligned.
SQLITE_DDL = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY, started_at TEXT NOT NULL,
    config_hash TEXT NOT NULL, summary_json TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS hosts (
    run_id TEXT NOT NULL, ip TEXT NOT NULL, json TEXT NOT NULL,
    PRIMARY KEY (run_id, ip));
CREATE TABLE IF NOT EXISTS finding_runs (
    run_id TEXT NOT NULL, finding_id TEXT NOT NULL, seen_at TEXT NOT NULL,
    PRIMARY KEY (run_id, finding_id));
CREATE INDEX IF NOT EXISTS finding_runs_finding ON finding_runs (finding_id);
CREATE TABLE IF NOT EXISTS enrichments (
    finding_id TEXT NOT NULL, cve_id TEXT NOT NULL, json TEXT NOT NULL,
    PRIMARY KEY (finding_id, cve_id));
CREATE TABLE IF NOT EXISTS context_profiles (
    run_id TEXT NOT NULL, host_ip TEXT NOT NULL, json TEXT NOT NULL,
    PRIMARY KEY (run_id, host_ip));
CREATE TABLE IF NOT EXISTS scores (
    run_id TEXT NOT NULL, finding_id TEXT NOT NULL, json TEXT NOT NULL,
    risk REAL NOT NULL, band TEXT NOT NULL, PRIMARY KEY (run_id, finding_id));
CREATE TABLE IF NOT EXISTS rationales (
    run_id TEXT NOT NULL, finding_id TEXT NOT NULL, json TEXT NOT NULL,
    PRIMARY KEY (run_id, finding_id));
CREATE TABLE IF NOT EXISTS cve (
    id TEXT PRIMARY KEY, json TEXT NOT NULL, cvss31_base REAL, cvss40_base REAL);
CREATE TABLE IF NOT EXISTS epss (
    cve TEXT PRIMARY KEY, epss REAL, percentile REAL, score_date TEXT);
CREATE TABLE IF NOT EXISTS kev (cve TEXT PRIMARY KEY, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS feeds_meta (
    feed TEXT PRIMARY KEY, path TEXT NOT NULL, sha256 TEXT NOT NULL,
    file_date TEXT, rows INTEGER NOT NULL, loaded_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS assessment_targets (
    id TEXT PRIMARY KEY, label TEXT NOT NULL, scope_ref TEXT NOT NULL,
    target_kind TEXT NOT NULL CHECK (target_kind IN ('domain','ip','cidr','application')),
    target_value TEXT NOT NULL, authorization_ref TEXT NOT NULL,
    engagement_id TEXT REFERENCES engagements (id) ON DELETE CASCADE,
    entry_kind TEXT NOT NULL DEFAULT 'target'
        CHECK (entry_kind IN ('target','canary','exclusion')),
    owner_note TEXT, expires_at TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (scope_ref, target_kind, target_value));
CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY, target_id TEXT NOT NULL REFERENCES assessment_targets (id) ON DELETE CASCADE,
    run_id TEXT, address TEXT, hostname TEXT, asset_role TEXT,
    criticality TEXT CHECK (criticality IN ('low','medium','high','critical')),
    owner_note TEXT, tags TEXT NOT NULL DEFAULT '[]',
    mac TEXT, os_guess TEXT, environment TEXT CHECK (environment IN ('prod','test','dev')),
    source_scan_id TEXT, observed_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS assets_target ON assets (target_id, observed_at DESC);
CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY, asset_id TEXT NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    transport TEXT NOT NULL CHECK (transport IN ('tcp','udp')),
    name TEXT, product TEXT, version TEXT, cpe TEXT,
    tls INTEGER NOT NULL DEFAULT 0, observed_at TEXT NOT NULL,
    UNIQUE (asset_id, port, transport));
CREATE TABLE IF NOT EXISTS service_observations (
    id TEXT PRIMARY KEY, asset_id TEXT NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    scan_job_id TEXT, port INTEGER NOT NULL, transport TEXT NOT NULL,
    name TEXT, product TEXT, version TEXT, cpe TEXT,
    tls INTEGER NOT NULL DEFAULT 0, banner TEXT,
    state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open','closed','filtered')),
    evidence_source TEXT NOT NULL, observed_at TEXT NOT NULL,
    UNIQUE (asset_id, port, transport, observed_at));
CREATE INDEX IF NOT EXISTS service_observations_asset
    ON service_observations (asset_id, port, transport, observed_at DESC);
CREATE TABLE IF NOT EXISTS asset_relationships (
    id TEXT PRIMARY KEY,
    from_asset TEXT NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    to_asset TEXT NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    relation TEXT NOT NULL CHECK (relation IN ('hosts','connects_to','depends_on','backed_by')),
    evidence TEXT NOT NULL DEFAULT '{}', scan_job_id TEXT, created_at TEXT NOT NULL,
    UNIQUE (from_asset, to_asset, relation),
    CHECK (from_asset <> to_asset));
CREATE TABLE IF NOT EXISTS scan_jobs (
    id TEXT PRIMARY KEY, target_id TEXT NOT NULL REFERENCES assessment_targets (id) ON DELETE RESTRICT,
    run_id TEXT, tool TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('planned','running','completed','failed','cancelled')),
    requested_at TEXT NOT NULL, started_at TEXT, completed_at TEXT,
    scope_snapshot_id TEXT REFERENCES scope_snapshots (id) ON DELETE SET NULL,
    scope_snapshot TEXT NOT NULL, command_summary TEXT NOT NULL,
    result_summary TEXT NOT NULL DEFAULT '{}',
    operator TEXT, tool_version TEXT, error_summary TEXT,
    result_counts TEXT NOT NULL DEFAULT '{}', content_sha256 TEXT);
CREATE INDEX IF NOT EXISTS scan_jobs_target ON scan_jobs (target_id, requested_at DESC);
CREATE TRIGGER IF NOT EXISTS scan_jobs_target_kind_trigger
BEFORE INSERT ON scan_jobs FOR EACH ROW
BEGIN
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM assessment_targets WHERE id = NEW.target_id AND entry_kind <> 'target')
    THEN RAISE(ABORT, 'scan target is a canary or exclusion entry and must not be scanned') END;
END;
CREATE TABLE IF NOT EXISTS scan_evidence (
    id TEXT PRIMARY KEY, scan_job_id TEXT NOT NULL REFERENCES scan_jobs (id) ON DELETE CASCADE,
    finding_id TEXT, evidence_type TEXT NOT NULL, excerpt TEXT NOT NULL,
    source_sha256 TEXT NOT NULL, captured_at TEXT NOT NULL, provenance TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS scan_evidence_finding ON scan_evidence (finding_id);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY, run_id TEXT NOT NULL, host_ip TEXT NOT NULL, tool TEXT NOT NULL,
    json TEXT NOT NULL DEFAULT '{}', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    asset_id TEXT, title TEXT, description TEXT,
    severity TEXT CHECK (severity IN ('critical','high','medium','low','info')),
    confidence REAL CHECK (confidence BETWEEN 0 AND 1),
    port INTEGER, url TEXT,
    lifecycle_status TEXT NOT NULL DEFAULT 'open'
        CHECK (lifecycle_status IN ('open','resolved')),
    resolved_at TEXT, recurrence_count INTEGER NOT NULL DEFAULT 0, scan_job_id TEXT);
CREATE INDEX IF NOT EXISTS findings_run ON findings (run_id);
CREATE TABLE IF NOT EXISTS model_evaluations (
    id TEXT PRIMARY KEY, run_id TEXT NOT NULL, model_name TEXT NOT NULL, model_hash TEXT,
    task TEXT NOT NULL, metrics TEXT NOT NULL, dataset_ref TEXT NOT NULL,
    evaluated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, owner_name TEXT NOT NULL, department TEXT,
    authorisation_ref TEXT NOT NULL UNIQUE,
    authorised_from TEXT NOT NULL, authorised_until TEXT NOT NULL,
    permitted_tools TEXT NOT NULL DEFAULT '[]', scan_restrictions TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('draft','active','expired','revoked')),
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    CHECK (authorised_until >= authorised_from));
CREATE TABLE IF NOT EXISTS scope_snapshots (
    id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    run_id TEXT, snapshot TEXT NOT NULL, sha256 TEXT NOT NULL, created_at TEXT NOT NULL,
    UNIQUE (engagement_id, run_id));
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, engagement_id TEXT, scan_job_id TEXT,
    event_type TEXT NOT NULL, actor TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}', occurred_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS finding_cves (
    finding_id TEXT NOT NULL, cve_id TEXT NOT NULL, source_tool TEXT NOT NULL,
    confidence REAL, created_at TEXT NOT NULL,
    PRIMARY KEY (finding_id, cve_id));
CREATE TABLE IF NOT EXISTS finding_cwes (
    finding_id TEXT NOT NULL, cwe_id TEXT NOT NULL CHECK (cwe_id LIKE 'CWE-%'),
    source TEXT NOT NULL DEFAULT 'scanner', created_at TEXT NOT NULL,
    PRIMARY KEY (finding_id, cwe_id));
CREATE TABLE IF NOT EXISTS finding_assets (
    finding_id TEXT NOT NULL, asset_id TEXT NOT NULL, created_at TEXT NOT NULL,
    PRIMARY KEY (finding_id, asset_id));
CREATE TABLE IF NOT EXISTS vuln_intel (
    cve_id TEXT PRIMARY KEY,
    cvss31_vector TEXT, cvss31_base REAL, cvss40_vector TEXT, cvss40_base REAL,
    epss_score REAL, epss_percentile REAL, epss_date TEXT,
    in_kev INTEGER NOT NULL DEFAULT 0, kev_date_added TEXT,
    exploit_maturity TEXT NOT NULL DEFAULT 'none'
        CHECK (exploit_maturity IN ('none','poc','functional','weaponized')),
    patch_references TEXT NOT NULL DEFAULT '[]', remediation_guidance TEXT,
    feed_source TEXT NOT NULL, feed_date TEXT, fetched_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS role_predictions (
    id TEXT PRIMARY KEY, run_id TEXT NOT NULL, host_ip TEXT NOT NULL,
    predicted_role TEXT NOT NULL, confidence REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    features TEXT NOT NULL DEFAULT '{}', evidence TEXT NOT NULL DEFAULT '[]',
    model_version TEXT NOT NULL, model_hash TEXT NOT NULL,
    disposition TEXT NOT NULL DEFAULT 'shadow'
        CHECK (disposition IN ('accepted','rejected','shadow')),
    decided_by TEXT, decided_at TEXT, created_at TEXT NOT NULL,
    UNIQUE (run_id, host_ip, model_hash));
CREATE TABLE IF NOT EXISTS context_signals (
    id TEXT PRIMARY KEY, run_id TEXT NOT NULL, host_ip TEXT NOT NULL,
    signal_kind TEXT NOT NULL CHECK (signal_kind IN
        ('exposure','control','criticality','environment','override')),
    value TEXT NOT NULL, confidence REAL, source TEXT NOT NULL
        CHECK (source IN ('model','config','manual','scanner')),
    evidence TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS score_history (
    id TEXT PRIMARY KEY, run_id TEXT NOT NULL, finding_id TEXT NOT NULL,
    weights_hash TEXT NOT NULL, formula_version TEXT NOT NULL,
    cvss_inputs TEXT NOT NULL DEFAULT '{}', epss_input TEXT NOT NULL DEFAULT '{}',
    kev_input INTEGER NOT NULL DEFAULT 0, environmental TEXT NOT NULL DEFAULT '{}',
    risk REAL NOT NULL CHECK (risk BETWEEN 0 AND 100), band TEXT NOT NULL,
    explanation TEXT NOT NULL, recommendation TEXT,
    calculated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS score_history_finding ON score_history (finding_id, calculated_at DESC);
CREATE TABLE IF NOT EXISTS analyst_suggestions (
    id TEXT PRIMARY KEY, run_id TEXT NOT NULL, finding_id TEXT, host_ip TEXT,
    model TEXT NOT NULL, suggestion TEXT NOT NULL, cited_evidence TEXT NOT NULL DEFAULT '[]',
    is_advisory INTEGER NOT NULL DEFAULT 1 CHECK (is_advisory = 1),
    created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS review_decisions (
    id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, run_id TEXT,
    reviewer TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN
        ('accepted','false_positive','needs_investigation','remediated',
         'risk_accepted','duplicate','out_of_scope')),
    justification TEXT NOT NULL CHECK (length(justification) <= 4000),
    supporting_evidence TEXT NOT NULL DEFAULT '[]',
    remediation_owner TEXT, remediation_due TEXT, decided_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS review_decisions_finding ON review_decisions (finding_id, decided_at DESC);
CREATE TABLE IF NOT EXISTS remediation_tracking (
    id TEXT PRIMARY KEY, finding_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'planned' CHECK (status IN
        ('planned','in_progress','pending_verification','verified','rejected')),
    owner TEXT, verification_run_id TEXT, evidence TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS comments (
    id TEXT PRIMARY KEY, finding_id TEXT, run_id TEXT, author TEXT NOT NULL,
    body TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 4000), created_at TEXT NOT NULL,
    CHECK (finding_id IS NOT NULL OR run_id IS NOT NULL));
CREATE TABLE IF NOT EXISTS datasets (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, version TEXT NOT NULL, source TEXT NOT NULL,
    data_kind TEXT NOT NULL CHECK (data_kind IN ('synthetic','real_authorised')),
    reviewer TEXT, quality TEXT NOT NULL DEFAULT 'draft'
        CHECK (quality IN ('draft','reviewed','approved')),
    config_hash TEXT NOT NULL, content_sha256 TEXT NOT NULL,
    row_count INTEGER NOT NULL CHECK (row_count >= 0), created_at TEXT NOT NULL,
    UNIQUE (name, version, content_sha256));
CREATE TABLE IF NOT EXISTS ground_truth_labels (
    id TEXT PRIMARY KEY, dataset_id TEXT NOT NULL, subject_kind TEXT NOT NULL
        CHECK (subject_kind IN ('host_role','exposure','control','priority')),
    subject_key TEXT NOT NULL, label TEXT NOT NULL, annotated_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (dataset_id, subject_kind, subject_key));
CREATE TABLE IF NOT EXISTS role_model_runs (
    id TEXT PRIMARY KEY, dataset_id TEXT NOT NULL, model_name TEXT NOT NULL,
    model_hash TEXT NOT NULL, label_set TEXT NOT NULL, split TEXT NOT NULL,
    accuracy REAL, macro_f1 REAL, per_class TEXT NOT NULL DEFAULT '{}',
    coverage REAL, abstention_rate REAL, confusion TEXT NOT NULL DEFAULT '{}',
    evaluated_at TEXT NOT NULL, notes TEXT);
CREATE TABLE IF NOT EXISTS ablation_experiments (
    id TEXT PRIMARY KEY, dataset_id TEXT NOT NULL,
    variant TEXT NOT NULL CHECK (variant IN ('cvss_only','cvss_epss','full_context')),
    config_hash TEXT NOT NULL, metrics TEXT NOT NULL DEFAULT '{}',
    ranking TEXT NOT NULL DEFAULT '[]', ranking_changes TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    UNIQUE (dataset_id, variant, config_hash));
CREATE TABLE IF NOT EXISTS retention_policies (
    table_name TEXT PRIMARY KEY, retention_days INTEGER NOT NULL CHECK (retention_days > 0),
    basis TEXT NOT NULL, updated_at TEXT NOT NULL);
"""


_last_now = ""


def _now() -> str:
    # Microsecond precision plus a monotonic guard: Windows clocks tick at
    # ~15ms, so consecutive writes could otherwise share one timestamp and
    # break ordering-dependent history (score history, service observations).
    global _last_now
    value = datetime.now(UTC).isoformat(timespec="microseconds")
    if value <= _last_now:
        value = (datetime.fromisoformat(_last_now) + timedelta(microseconds=1)).isoformat(
            timespec="microseconds"
        )
    _last_now = value
    return value


def resolve_backend(value: str | Path | None = None) -> str | Path:
    """Return a SQLite path or a PostgreSQL URL, honouring VULNASS_DATABASE_URL.

    An explicit PostgreSQL URL or ``env:`` reference wins; an unset value falls
    back to ``env:VULNASS_DATABASE_URL`` when set, otherwise the default
    SQLite path. An explicit SQLite path always stays SQLite.
    """
    text = str(value) if value is not None else ""
    if text.startswith("env:"):
        name = text.removeprefix("env:")
        if not name or not name.isidentifier():
            raise ConfigError("database environment variable name is invalid")
        url = os.environ.get(name)
        if not url:
            raise ConfigError(f"MISSING: database URL environment variable {name}")
        if not url.startswith(("postgresql://", "postgres://")):
            raise ConfigError(f"database environment variable {name} is not a PostgreSQL URL")
        return url
    if text.startswith(("postgresql://", "postgres://")):
        return text
    if not text:
        url = os.environ.get(ENV_VAR, "")
        if url:
            if not url.startswith(("postgresql://", "postgres://")):
                raise ConfigError(f"{ENV_VAR} is not a PostgreSQL URL")
            return url
        return Path("data/vulnassess.db")
    return Path(text)


class AssessmentRepository:
    """Parameterised access to the expanded assessment schema."""

    def __init__(self, database: str | Path | None = None, *, read_only: bool = False) -> None:
        self.connection: Any
        self.backend = resolve_backend(database)
        self.read_only = read_only
        if isinstance(self.backend, str):
            self._dialect = "postgres"
            self._pg_connect(self.backend)
        else:
            self._dialect = "sqlite"
            self._sqlite_connect(Path(self.backend))

    def _pg_connect(self, url: str) -> None:
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as error:
            raise ConfigError(
                "MISSING: install psycopg to use a PostgreSQL assessment store"
            ) from error
        try:
            connect: Any = psycopg.connect
            self.connection = connect(url, row_factory=dict_row)
            if self.read_only:
                with self.connection.cursor() as cursor:
                    cursor.execute("set default_transaction_read_only = on")
                self.connection.commit()
        except Exception as error:
            raise ConfigError("cannot open the configured PostgreSQL assessment store") from error

    def _sqlite_connect(self, path: Path) -> None:
        if self.read_only:
            if not path.is_file():
                raise ConfigError(f"MISSING: SQLite database {path}")
            try:
                self.connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
            except sqlite3.Error as error:
                raise ConfigError(f"cannot open read-only SQLite database {path}") from error
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA query_only = ON")
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(path))
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SQLITE_DDL)
        self.connection.commit()
        self._sqlite_backfill()

    def _sqlite_backfill(self) -> None:
        """Add the expanded findings columns to a legacy SQLite store in place."""
        existing = {row[1] for row in self.connection.execute("PRAGMA table_info(findings)")}
        columns = {
            "asset_id": "TEXT",
            "title": "TEXT",
            "description": "TEXT",
            "severity": "TEXT",
            "confidence": "REAL",
            "port": "INTEGER",
            "url": "TEXT",
            "lifecycle_status": "TEXT NOT NULL DEFAULT 'open'",
            "resolved_at": "TEXT",
            "recurrence_count": "INTEGER NOT NULL DEFAULT 0",
            "scan_job_id": "TEXT",
        }
        for name, kind in columns.items():
            if name not in existing:
                self.connection.execute(f"ALTER TABLE findings ADD COLUMN {name} {kind}")
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "AssessmentRepository":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # dialect helpers ---------------------------------------------------
    def _sql(self, query: str) -> str:
        if self._dialect == "postgres":
            return query.replace("{INET}", "?::inet").replace("?", "%s")
        return query.replace("{INET}", "?")

    def _exec(self, query: str, parameters: tuple[Any, ...] = ()) -> None:
        sql = self._sql(query)
        try:
            if self._dialect == "postgres":
                with self.connection.cursor() as cursor:
                    cursor.execute(sql, parameters)
            else:
                self.connection.execute(sql, parameters)
            self.connection.commit()
        except Exception as error:
            try:
                self.connection.rollback()
            except Exception:
                pass
            raise ConfigError(f"assessment store write failed: {error}") from error

    def _rows(self, query: str, parameters: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        sql = self._sql(query)
        try:
            if self._dialect == "postgres":
                with self.connection.cursor() as cursor:
                    cursor.execute(sql, parameters)
                    rows = list(cursor.fetchall())
            else:
                rows = [dict(row) for row in self.connection.execute(sql, parameters).fetchall()]
        except Exception as error:
            raise ConfigError(f"assessment store read failed: {error}") from error
        return [_json_values(row) for row in rows]

    def _one(self, query: str, parameters: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        rows = self._rows(query, parameters)
        return rows[0] if rows else None

    # governance --------------------------------------------------------
    def add_engagement(self, record: dict[str, Any]) -> str:
        engagement_id = record.get("id") or str(uuid.uuid4())
        self._exec(
            "insert into engagements (id, name, owner_name, department, authorisation_ref, "
            "authorised_from, authorised_until, permitted_tools, scan_restrictions, status, "
            "created_at, updated_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "on conflict (id) do update set updated_at = excluded.updated_at",
            (
                engagement_id,
                record["name"],
                record["owner_name"],
                record.get("department"),
                record["authorisation_ref"],
                record["authorised_from"],
                record["authorised_until"],
                _encode(record.get("permitted_tools", []), self._dialect, "array"),
                _encode(record.get("scan_restrictions", {}), self._dialect),
                record.get("status", "active"),
                _now(),
                _now(),
            ),
        )
        self.audit(
            "engagement.created",
            actor=record.get("owner_name", "backend"),
            engagement_id=engagement_id,
        )
        return engagement_id

    def add_scope_entry(self, engagement_id: str, record: dict[str, Any]) -> str:
        entry_id = record.get("id") or str(uuid.uuid4())
        self._exec(
            "insert into assessment_targets (id, label, scope_ref, target_kind, target_value, "
            "authorization_ref, engagement_id, entry_kind, owner_note, expires_at, created_at) "
            "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "on conflict (scope_ref, target_kind, target_value) do update set "
            "entry_kind = excluded.entry_kind, owner_note = excluded.owner_note",
            (
                entry_id,
                record["label"],
                record.get("scope_ref", engagement_id),
                record["target_kind"],
                record["target_value"],
                record["authorization_ref"],
                engagement_id,
                record.get("entry_kind", "target"),
                record.get("owner_note"),
                record.get("expires_at"),
                _now(),
            ),
        )
        self.audit(
            "scope.entry_added",
            actor=record.get("actor", "backend"),
            engagement_id=engagement_id,
            detail={
                "entry_kind": record.get("entry_kind", "target"),
                "target_value": record["target_value"],
            },
        )
        return entry_id

    def record_scope_snapshot(
        self, engagement_id: str, run_id: str | None, snapshot: dict[str, Any], sha256: str
    ) -> str:
        snapshot_id = str(uuid.uuid4())
        self._exec(
            "insert into scope_snapshots (id, engagement_id, run_id, snapshot, sha256, created_at) "
            "values (?, ?, ?, ?, ?, ?) on conflict (engagement_id, run_id) do update set "
            "snapshot = excluded.snapshot, sha256 = excluded.sha256",
            (snapshot_id, engagement_id, run_id, _encode(snapshot, self._dialect), sha256, _now()),
        )
        return snapshot_id

    def request_scan(self, record: dict[str, Any]) -> str:
        """Plan a scan job. Refuses canary/exclusion targets via a DB trigger."""
        job_id = record.get("id") or str(uuid.uuid4())
        self._exec(
            "insert into scan_jobs (id, target_id, run_id, tool, status, requested_at, "
            "scope_snapshot_id, scope_snapshot, command_summary, operator, tool_version) "
            "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                job_id,
                record["target_id"],
                record.get("run_id"),
                record["tool"],
                record.get("status", "planned"),
                _now(),
                record.get("scope_snapshot_id"),
                _encode(record.get("scope_snapshot", {}), self._dialect),
                record["command_summary"],
                record.get("operator"),
                record.get("tool_version"),
            ),
        )
        self.audit(
            "scan.requested",
            actor=record.get("operator", "backend"),
            run_id=record.get("run_id"),
            scan_job_id=job_id,
            detail={"tool": record["tool"]},
        )
        return job_id

    def complete_scan(
        self,
        job_id: str,
        status: str,
        result_counts: dict[str, Any],
        content_sha256: str,
        error_summary: str | None = None,
    ) -> None:
        self._exec(
            "update scan_jobs set status = ?, completed_at = ?, result_counts = ?, "
            "content_sha256 = ?, error_summary = ? where id = ?",
            (
                status,
                _now(),
                _encode(result_counts, self._dialect),
                content_sha256,
                error_summary,
                job_id,
            ),
        )
        self.audit("scan.completed", actor="backend", scan_job_id=job_id, detail={"status": status})

    def add_evidence(
        self,
        job_id: str,
        finding_id: str | None,
        evidence_type: str,
        excerpt: str,
        source_sha256: str,
        provenance: dict[str, Any] | None = None,
    ) -> str:
        evidence_id = str(uuid.uuid4())
        self._exec(
            "insert into scan_evidence (id, scan_job_id, finding_id, evidence_type, excerpt, "
            "source_sha256, captured_at, provenance) values (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                evidence_id,
                job_id,
                finding_id,
                evidence_type,
                excerpt[:2000],
                source_sha256,
                _now(),
                _encode(provenance or {}, self._dialect),
            ),
        )
        return evidence_id

    def audit(
        self,
        event_type: str,
        actor: str = "backend",
        *,
        run_id: str | None = None,
        engagement_id: str | None = None,
        scan_job_id: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        self._exec(
            "insert into audit_events (run_id, engagement_id, scan_job_id, event_type, actor, "
            "detail, occurred_at) values (?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                engagement_id,
                scan_job_id,
                event_type,
                actor,
                _encode(detail or {}, self._dialect),
                _now(),
            ),
        )

    # assets ------------------------------------------------------------
    def record_asset(self, record: dict[str, Any]) -> str:
        asset_id = record.get("id") or str(uuid.uuid4())
        self._exec(
            "insert into assets (id, target_id, run_id, address, hostname, asset_role, "
            "criticality, owner_note, tags, mac, os_guess, environment, source_scan_id, "
            "observed_at) values (?, ?, ?, {INET}, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                asset_id,
                record["target_id"],
                record.get("run_id"),
                record.get("address"),
                record.get("hostname"),
                record.get("asset_role"),
                record.get("criticality"),
                record.get("owner_note"),
                _encode(record.get("tags", []), self._dialect),
                record.get("mac"),
                record.get("os_guess"),
                record.get("environment"),
                record.get("source_scan_id"),
                _now(),
            ),
        )
        return asset_id

    def observe_service(self, record: dict[str, Any]) -> str:
        """Append a historical service observation (never overwrites)."""
        observation_id = str(uuid.uuid4())
        observed_at = record.get("observed_at", _now())
        self._exec(
            "insert into service_observations (id, asset_id, scan_job_id, port, transport, "
            "name, product, version, cpe, tls, banner, state, evidence_source, observed_at) "
            "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "on conflict (asset_id, port, transport, observed_at) do nothing",
            (
                observation_id,
                record["asset_id"],
                record.get("scan_job_id"),
                record["port"],
                record.get("transport", "tcp"),
                record.get("name"),
                record.get("product"),
                record.get("version"),
                record.get("cpe"),
                int(bool(record.get("tls"))),
                record.get("banner"),
                record.get("state", "open"),
                record["evidence_source"],
                observed_at,
            ),
        )
        return observation_id

    def relate_assets(
        self,
        from_asset: str,
        to_asset: str,
        relation: str,
        evidence: dict[str, Any] | None = None,
        scan_job_id: str | None = None,
    ) -> str:
        relationship_id = str(uuid.uuid4())
        self._exec(
            "insert into asset_relationships (id, from_asset, to_asset, relation, evidence, "
            "scan_job_id, created_at) values (?, ?, ?, ?, ?, ?, ?) "
            "on conflict (from_asset, to_asset, relation) do update set "
            "evidence = excluded.evidence",
            (
                relationship_id,
                from_asset,
                to_asset,
                relation,
                _encode(evidence or {}, self._dialect),
                scan_job_id,
                _now(),
            ),
        )
        return relationship_id

    # findings and intel -------------------------------------------------
    def link_finding_cve(
        self, finding_id: str, cve_id: str, source_tool: str, confidence: float | None = None
    ) -> None:
        self._exec(
            "insert into finding_cves (finding_id, cve_id, source_tool, confidence, created_at) "
            "values (?, ?, ?, ?, ?) on conflict (finding_id, cve_id) do update set "
            "source_tool = excluded.source_tool, confidence = excluded.confidence",
            (finding_id, cve_id, source_tool, confidence, _now()),
        )

    def link_finding_cwe(self, finding_id: str, cwe_id: str, source: str = "scanner") -> None:
        self._exec(
            "insert into finding_cwes (finding_id, cwe_id, source, created_at) "
            "values (?, ?, ?, ?) on conflict (finding_id, cwe_id) do nothing",
            (finding_id, cwe_id, source, _now()),
        )

    def link_finding_asset(self, finding_id: str, asset_id: str) -> None:
        self._exec(
            "insert into finding_assets (finding_id, asset_id, created_at) values (?, ?, ?) "
            "on conflict (finding_id, asset_id) do nothing",
            (finding_id, asset_id, _now()),
        )

    def put_vuln_intel(self, record: dict[str, Any]) -> None:
        self._exec(
            "insert into vuln_intel (cve_id, cvss31_vector, cvss31_base, cvss40_vector, "
            "cvss40_base, epss_score, epss_percentile, epss_date, in_kev, kev_date_added, "
            "exploit_maturity, patch_references, remediation_guidance, feed_source, feed_date, "
            "fetched_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "on conflict (cve_id) do update set epss_score = excluded.epss_score, "
            "epss_percentile = excluded.epss_percentile, epss_date = excluded.epss_date, "
            "in_kev = excluded.in_kev, exploit_maturity = excluded.exploit_maturity, "
            "patch_references = excluded.patch_references, feed_source = excluded.feed_source, "
            "feed_date = excluded.feed_date, fetched_at = excluded.fetched_at",
            (
                record["cve_id"],
                record.get("cvss31_vector"),
                record.get("cvss31_base"),
                record.get("cvss40_vector"),
                record.get("cvss40_base"),
                record.get("epss_score"),
                record.get("epss_percentile"),
                record.get("epss_date"),
                int(bool(record.get("in_kev"))),
                record.get("kev_date_added"),
                record.get("exploit_maturity", "none"),
                _encode(record.get("patch_references", []), self._dialect),
                record.get("remediation_guidance"),
                record["feed_source"],
                record.get("feed_date"),
                _now(),
            ),
        )

    # scoring and explainability ------------------------------------------
    def record_role_prediction(self, record: dict[str, Any]) -> str:
        prediction_id = str(uuid.uuid4())
        self._exec(
            "insert into role_predictions (id, run_id, host_ip, predicted_role, confidence, "
            "features, evidence, model_version, model_hash, disposition, decided_by, "
            "decided_at, created_at) values (?, ?, {INET}, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "on conflict (run_id, host_ip, model_hash) do update set "
            "disposition = excluded.disposition, decided_by = excluded.decided_by",
            (
                prediction_id,
                record["run_id"],
                record["host_ip"],
                record["predicted_role"],
                record["confidence"],
                _encode(record.get("features", {}), self._dialect),
                _encode(record.get("evidence", []), self._dialect),
                record["model_version"],
                record["model_hash"],
                record.get("disposition", "shadow"),
                record.get("decided_by"),
                record.get("decided_at"),
                _now(),
            ),
        )
        return prediction_id

    def record_context_signal(self, record: dict[str, Any]) -> str:
        signal_id = str(uuid.uuid4())
        self._exec(
            "insert into context_signals (id, run_id, host_ip, signal_kind, value, confidence, "
            "source, evidence, created_at) values (?, ?, {INET}, ?, ?, ?, ?, ?, ?)",
            (
                signal_id,
                record["run_id"],
                record["host_ip"],
                record["signal_kind"],
                _encode(record["value"], self._dialect),
                record.get("confidence"),
                record["source"],
                _encode(record.get("evidence", {}), self._dialect),
                _now(),
            ),
        )
        return signal_id

    def record_score(self, record: dict[str, Any]) -> str:
        """Append to score history; every calculation is preserved."""
        history_id = str(uuid.uuid4())
        self._exec(
            "insert into score_history (id, run_id, finding_id, weights_hash, formula_version, "
            "cvss_inputs, epss_input, kev_input, environmental, risk, band, explanation, "
            "recommendation, calculated_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                history_id,
                record["run_id"],
                record["finding_id"],
                record["weights_hash"],
                record.get("formula_version", "1"),
                _encode(record.get("cvss_inputs", {}), self._dialect),
                _encode(record.get("epss_input", {}), self._dialect),
                int(bool(record.get("kev_input"))),
                _encode(record.get("environmental", {}), self._dialect),
                record["risk"],
                record["band"],
                record["explanation"],
                record.get("recommendation"),
                _now(),
            ),
        )
        return history_id

    def add_analyst_suggestion(self, record: dict[str, Any]) -> str:
        """Store a local-LLM suggestion. Advisory-only, enforced by the schema."""
        suggestion_id = str(uuid.uuid4())
        self._exec(
            "insert into analyst_suggestions (id, run_id, finding_id, host_ip, model, "
            "suggestion, cited_evidence, is_advisory, created_at) "
            "values (?, ?, ?, {INET}, ?, ?, ?, 1, ?)",
            (
                suggestion_id,
                record["run_id"],
                record.get("finding_id"),
                record.get("host_ip"),
                record["model"],
                record["suggestion"],
                _encode(record.get("cited_evidence", []), self._dialect),
                _now(),
            ),
        )
        return suggestion_id

    # review workflow -----------------------------------------------------
    def add_review_decision(self, record: dict[str, Any]) -> str:
        decision_id = str(uuid.uuid4())
        self._exec(
            "insert into review_decisions (id, finding_id, run_id, reviewer, decision, "
            "justification, supporting_evidence, remediation_owner, remediation_due, decided_at) "
            "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                decision_id,
                record["finding_id"],
                record.get("run_id"),
                record["reviewer"],
                record["decision"],
                record["justification"],
                _encode(record.get("supporting_evidence", []), self._dialect),
                record.get("remediation_owner"),
                record.get("remediation_due"),
                _now(),
            ),
        )
        self.audit(
            "review.decision",
            actor=record["reviewer"],
            run_id=record.get("run_id"),
            detail={"decision": record["decision"]},
        )
        return decision_id

    def set_remediation_status(
        self,
        finding_id: str,
        status: str,
        *,
        owner: str | None = None,
        verification_run_id: str | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> str:
        tracking_id = str(uuid.uuid4())
        self._exec(
            "insert into remediation_tracking (id, finding_id, status, owner, "
            "verification_run_id, evidence, created_at, updated_at) "
            "values (?, ?, ?, ?, ?, ?, ?, ?) "
            "on conflict (finding_id) do update set status = excluded.status, "
            "owner = excluded.owner, verification_run_id = excluded.verification_run_id, "
            "evidence = excluded.evidence, updated_at = excluded.updated_at",
            (
                tracking_id,
                finding_id,
                status,
                owner,
                verification_run_id,
                _encode(evidence or {}, self._dialect),
                _now(),
                _now(),
            ),
        )
        return tracking_id

    def add_comment(self, record: dict[str, Any]) -> str:
        comment_id = str(uuid.uuid4())
        self._exec(
            "insert into comments (id, finding_id, run_id, author, body, created_at) "
            "values (?, ?, ?, ?, ?, ?)",
            (
                comment_id,
                record.get("finding_id"),
                record.get("run_id"),
                record["author"],
                record["body"],
                _now(),
            ),
        )
        return comment_id

    # research ------------------------------------------------------------
    def add_dataset(self, record: dict[str, Any]) -> str:
        dataset_id = record.get("id") or str(uuid.uuid4())
        self._exec(
            "insert into datasets (id, name, version, source, data_kind, reviewer, quality, "
            "config_hash, content_sha256, row_count, created_at) "
            "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "on conflict (name, version, content_sha256) do nothing",
            (
                dataset_id,
                record["name"],
                record["version"],
                record["source"],
                record["data_kind"],
                record.get("reviewer"),
                record.get("quality", "draft"),
                record["config_hash"],
                record["content_sha256"],
                record.get("row_count", 0),
                _now(),
            ),
        )
        return dataset_id

    def add_ground_truth(
        self, dataset_id: str, subject_kind: str, subject_key: str, label: str, annotated_by: str
    ) -> str:
        label_id = str(uuid.uuid4())
        self._exec(
            "insert into ground_truth_labels (id, dataset_id, subject_kind, subject_key, label, "
            "annotated_by, created_at) values (?, ?, ?, ?, ?, ?, ?) "
            "on conflict (dataset_id, subject_kind, subject_key) do update set "
            "label = excluded.label",
            (label_id, dataset_id, subject_kind, subject_key, label, annotated_by, _now()),
        )
        return label_id

    def add_role_model_run(self, record: dict[str, Any]) -> str:
        run_pk = str(uuid.uuid4())
        self._exec(
            "insert into role_model_runs (id, dataset_id, model_name, model_hash, label_set, "
            "split, accuracy, macro_f1, per_class, coverage, abstention_rate, confusion, "
            "evaluated_at, notes) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_pk,
                record["dataset_id"],
                record["model_name"],
                record["model_hash"],
                _encode(record.get("label_set", []), self._dialect, "array"),
                _encode(record.get("split", {}), self._dialect),
                record.get("accuracy"),
                record.get("macro_f1"),
                _encode(record.get("per_class", {}), self._dialect),
                record.get("coverage"),
                record.get("abstention_rate"),
                _encode(record.get("confusion", {}), self._dialect),
                _now(),
                record.get("notes"),
            ),
        )
        return run_pk

    def add_ablation(self, record: dict[str, Any]) -> str:
        ablation_id = str(uuid.uuid4())
        self._exec(
            "insert into ablation_experiments (id, dataset_id, variant, config_hash, metrics, "
            "ranking, ranking_changes, created_at) values (?, ?, ?, ?, ?, ?, ?, ?) "
            "on conflict (dataset_id, variant, config_hash) do update set "
            "metrics = excluded.metrics, ranking = excluded.ranking, "
            "ranking_changes = excluded.ranking_changes",
            (
                ablation_id,
                record["dataset_id"],
                record["variant"],
                record["config_hash"],
                _encode(record.get("metrics", {}), self._dialect),
                _encode(record.get("ranking", []), self._dialect),
                _encode(record.get("ranking_changes", []), self._dialect),
                _now(),
            ),
        )
        return ablation_id

    # read API (backing the GET-only dashboard routes) --------------------
    def assessment_runs(self) -> list[dict[str, Any]]:
        return self._rows(
            "select e.id as engagement_id, e.name, e.owner_name, e.authorisation_ref, "
            "e.authorised_until, e.status, e.permitted_tools, "
            "(select count(*) from assessment_targets t "
            " where t.engagement_id = e.id and t.entry_kind = 'target') as scope_entries, "
            "(select count(*) from scope_snapshots s where s.engagement_id = e.id) "
            " as snapshots "
            "from engagements e order by e.created_at desc"
        )

    def asset_inventory(self, run_id: str | None = None) -> list[dict[str, Any]]:
        query = (
            "select a.id, a.address, a.hostname, a.asset_role, a.criticality, a.environment, "
            "a.os_guess, a.tags, a.observed_at, t.label as target_label "
            "from assets a join assessment_targets t on t.id = a.target_id"
        )
        parameters: tuple[Any, ...] = ()
        if run_id is not None:
            query += " where a.run_id = ?"
            parameters = (run_id,)
        return self._rows(query + " order by a.observed_at desc", parameters)

    def asset_details(self, asset_id: str) -> dict[str, Any]:
        asset = self._one(
            "select a.*, t.label as target_label from assets a "
            "join assessment_targets t on t.id = a.target_id where a.id = ?",
            (asset_id,),
        )
        if asset is None:
            raise ConfigError(f"MISSING: asset {asset_id!r}")
        history = self._rows(
            "select port, transport, name, product, version, cpe, tls, banner, state, "
            "evidence_source, observed_at from service_observations "
            "where asset_id = ? order by observed_at desc, port",
            (asset_id,),
        )
        relationships = self._rows(
            "select r.relation, r.evidence, r.created_at, "
            "fa.address as from_address, ta.address as to_address "
            "from asset_relationships r "
            "join assets fa on fa.id = r.from_asset join assets ta on ta.id = r.to_asset "
            "where r.from_asset = ? or r.to_asset = ? order by r.created_at desc",
            (asset_id, asset_id),
        )
        return {"asset": asset, "service_history": history, "relationships": relationships}

    def findings_queue(
        self,
        run_id: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        decision: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        query = (
            "select f.id, f.host_ip, f.tool, f.title, f.severity, f.confidence, "
            "f.lifecycle_status, f.first_seen, f.last_seen, f.recurrence_count, "
            "(select d.decision from review_decisions d where d.finding_id = f.id "
            " order by d.decided_at desc limit 1) as latest_decision, "
            "(select h.risk from score_history h where h.finding_id = f.id "
            " order by h.calculated_at desc limit 1) as latest_risk, "
            "(select h.band from score_history h where h.finding_id = f.id "
            " order by h.calculated_at desc limit 1) as latest_band "
            "from findings f where 1 = 1"
        )
        parameters: list[Any] = []
        if run_id is not None:
            query += " and f.run_id = ?"
            parameters.append(run_id)
        if status is not None:
            query += " and f.lifecycle_status = ?"
            parameters.append(status)
        if severity is not None:
            query += " and f.severity = ?"
            parameters.append(severity)
        if decision is not None:
            query += (
                " and exists (select 1 from review_decisions d where d.finding_id = f.id "
                "and d.decision = ?)"
            )
            parameters.append(decision)
        query += " order by latest_risk desc nulls last, f.last_seen desc limit ?"
        parameters.append(min(max(int(limit), 1), 500))
        # SQLite does not support NULLS LAST before 3.30; both dialects we
        # support (SQLite >= 3.35, PostgreSQL) do.
        return self._rows(query, tuple(parameters))

    def finding_evidence(self, finding_id: str) -> dict[str, Any]:
        finding = self._one(
            "select id, host_ip, tool, title, severity, confidence, lifecycle_status, "
            "first_seen, last_seen from findings where id = ?",
            (finding_id,),
        )
        if finding is None:
            raise ConfigError(f"MISSING: finding {finding_id!r}")
        evidence = self._rows(
            "select e.id, e.evidence_type, e.excerpt, e.source_sha256, e.captured_at, "
            "e.provenance, j.tool, j.tool_version, j.command_summary, j.status as scan_status "
            "from scan_evidence e join scan_jobs j on j.id = e.scan_job_id "
            "where e.finding_id = ? order by e.captured_at desc",
            (finding_id,),
        )
        cves = self._rows(
            "select c.cve_id, c.source_tool, c.confidence, i.cvss31_base, i.epss_score, "
            "i.epss_percentile, i.in_kev, i.exploit_maturity, i.feed_source, i.feed_date "
            "from finding_cves c left join vuln_intel i on i.cve_id = c.cve_id "
            "where c.finding_id = ? order by c.cve_id",
            (finding_id,),
        )
        cwes = self._rows(
            "select cwe_id, source from finding_cwes where finding_id = ? order by cwe_id",
            (finding_id,),
        )
        reviews = self._rows(
            "select reviewer, decision, justification, decided_at from review_decisions "
            "where finding_id = ? order by decided_at desc",
            (finding_id,),
        )
        return {
            "finding": finding,
            "evidence": evidence,
            "cves": cves,
            "cwes": cwes,
            "reviews": reviews,
        }

    def finding_score_history(self, finding_id: str) -> dict[str, Any]:
        history = self._rows(
            "select run_id, weights_hash, formula_version, cvss_inputs, epss_input, kev_input, "
            "environmental, risk, band, explanation, recommendation, calculated_at "
            "from score_history where finding_id = ? order by calculated_at asc",
            (finding_id,),
        )
        if not history:
            raise ConfigError(f"MISSING: score history for finding {finding_id!r}")
        latest = history[-1]
        transitions = [
            {
                "from_band": history[index - 1]["band"],
                "to_band": history[index]["band"],
                "from_risk": history[index - 1]["risk"],
                "to_risk": history[index]["risk"],
                "run_id": history[index]["run_id"],
                "explanation": history[index]["explanation"],
            }
            for index in range(1, len(history))
            if history[index - 1]["band"] != history[index]["band"]
        ]
        return {
            "finding_id": finding_id,
            "history": history,
            "latest": latest,
            "band_transitions": transitions,
        }

    def model_evaluations(self) -> dict[str, Any]:
        runs = self._rows(
            "select m.id, m.dataset_id, m.model_name, m.model_hash, m.label_set, m.split, "
            "m.accuracy, m.macro_f1, m.per_class, m.coverage, m.abstention_rate, "
            "m.confusion, m.evaluated_at, m.notes, "
            "d.name as dataset_name, d.version as dataset_version, d.data_kind, d.quality "
            "from role_model_runs m join datasets d on d.id = m.dataset_id "
            "order by m.evaluated_at desc"
        )
        return {
            "role_model_runs": runs,
            "legacy_model_evaluations": self._rows(
                "select model_name, task, metrics, dataset_ref, evaluated_at "
                "from model_evaluations order by evaluated_at desc"
            ),
        }

    def ablation_summaries(self) -> list[dict[str, Any]]:
        return self._rows(
            "select a.variant, a.config_hash, a.metrics, a.ranking_changes, a.created_at, "
            "d.name as dataset_name, d.version as dataset_version "
            "from ablation_experiments a join datasets d on d.id = a.dataset_id "
            "order by d.created_at desc, a.variant"
        )

    def scope_entries(self, engagement_id: str) -> list[dict[str, Any]]:
        return self._rows(
            "select id, label, target_kind, target_value, entry_kind, owner_note, expires_at "
            "from assessment_targets where engagement_id = ? order by entry_kind, target_value",
            (engagement_id,),
        )


def _encode(value: Any, dialect: str, kind: str = "json") -> Any:
    if dialect == "postgres":
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _json_values(row: dict[str, Any]) -> dict[str, Any]:
    result = {}
    for key, value in row.items():
        if isinstance(value, str) and value[:1] in ("{", "["):
            try:
                result[key] = json.loads(value)
            except ValueError:
                result[key] = value
        else:
            result[key] = value
    return result
