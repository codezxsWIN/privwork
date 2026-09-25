"""Read stored assessment records without constructing the writable pipeline Store."""

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from vulnassess.errors import ConfigError

HOST_KEYS = frozenset({"ip", "hostname", "os_guess", "services"})
FINDING_KEYS = frozenset(
    {
        "id",
        "host_ip",
        "port",
        "protocol",
        "url",
        "tool",
        "tool_native_id",
        "title",
        "description",
        "evidence",
        "cve_ids",
        "cwe_ids",
        "reference_urls",
        "native_severity",
        "native_confidence",
        "first_seen",
        "last_seen",
        "provenance",
    }
)
SCORE_KEYS = frozenset(
    {
        "finding_id",
        "host_ip",
        "risk",
        "band",
        "reason",
        "fix",
        "weights_hash",
        "cve_id",
        "cvss_version_used",
        "base_vector",
        "base_score",
        "env_vector",
        "env_score",
        "env_modifications",
        "epss_percentile",
        "threat_multiplier",
        "kev",
        "native_fallback",
        "inputs",
    }
)


def local_path(value: str | Path) -> Path:
    text = str(value)
    if text.startswith(("\\\\", "//")):
        raise ConfigError(f"UI requires a local path, not a network share: {text}")
    path = Path(value).resolve()
    if str(path).startswith(("\\\\", "//")):
        raise ConfigError(f"UI requires a local path, not a network share: {path}")
    return path


def database_url(value: str | Path) -> str | None:
    """Resolve an opt-in backend PostgreSQL connection without exposing it to the UI."""
    text = str(value)
    if text.startswith(("postgresql://", "postgres://")):
        return text
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
    return None


def _invalid_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value}")


def _object(text: str, label: str, keys: frozenset[str] | None = None) -> dict[str, Any]:
    try:
        value = json.loads(text, parse_constant=_invalid_constant)
    except (ValueError, TypeError, RecursionError) as error:
        raise ConfigError(f"invalid stored JSON at {label}") from error
    if not isinstance(value, dict):
        raise ConfigError(f"expected a stored JSON object at {label}")
    if keys is not None and set(value) != keys:
        missing = sorted(keys - set(value))
        unknown = sorted(set(value) - keys)
        raise ConfigError(f"stored keys at {label}: missing={missing}; unknown={unknown}")
    return value


class ReadOnlyStore:
    def __init__(self, path: str | Path) -> None:
        self.path = local_path(path)
        if not self.path.is_file():
            raise ConfigError(f"MISSING: SQLite database {self.path}")
        try:
            self.connection = sqlite3.connect(f"{self.path.as_uri()}?mode=ro", uri=True)
        except sqlite3.Error as error:
            raise ConfigError(f"cannot open read-only SQLite database {self.path}") from error
        self.connection.row_factory = sqlite3.Row
        try:
            self.connection.execute("PRAGMA query_only = ON")
            self.connection.execute("BEGIN")
        except sqlite3.Error as error:
            self.connection.close()
            raise ConfigError(f"cannot begin read-only snapshot of {self.path}") from error

    def __enter__(self) -> "ReadOnlyStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.connection.close()

    def _rows(self, query: str, parameters: tuple[str, ...] = ()) -> list[sqlite3.Row]:
        try:
            return self.connection.execute(query, parameters).fetchall()
        except sqlite3.Error as error:
            raise ConfigError(f"cannot read stored UI records in {self.path}: {error}") from error

    def _run_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "run_id": row["run_id"],
            "started_at": row["started_at"],
            "config_hash": row["config_hash"],
            "summary": _object(row["summary_json"], f"{self.path}: runs.summary_json"),
        }

    def runs(self) -> list[dict[str, Any]]:
        return [
            self._run_row(row)
            for row in self._rows(
                "SELECT run_id, started_at, config_hash, summary_json FROM runs "
                "ORDER BY started_at DESC, run_id"
            )
        ]

    def run_info(self, run_id: str) -> dict[str, Any]:
        rows = self._rows(
            "SELECT run_id, started_at, config_hash, summary_json FROM runs WHERE run_id = ?",
            (run_id,),
        )
        if not rows:
            raise ConfigError(f"MISSING: run {run_id!r} in SQLite database {self.path}")
        return self._run_row(rows[0])

    def _records(
        self, query: str, run_id: str, label: str, keys: frozenset[str] | None = None
    ) -> list[dict[str, Any]]:
        return [
            _object(row["json"], f"{self.path}: {label}", keys)
            for row in self._rows(query, (run_id,))
        ]

    def unavailable(self, record: str, run_id: str) -> dict[str, Any]:
        return {
            "status": "MISSING",
            "records": None,
            "reason": (
                f"MISSING: persisted {record} for run {run_id!r} in {self.path}; "
                "the viewer does not calculate or create these records"
            ),
        }

    def run(self, run_id: str) -> dict[str, Any]:
        run = self.run_info(run_id)
        hosts = self._records(
            "SELECT json FROM hosts WHERE run_id = ? ORDER BY ip", run_id, "hosts", HOST_KEYS
        )
        findings = self._records(
            "SELECT f.json FROM findings f JOIN finding_runs r ON r.finding_id = f.id "
            "WHERE r.run_id = ? ORDER BY f.id",
            run_id,
            "findings",
            FINDING_KEYS,
        )
        scores = []
        for row in self._rows(
            "SELECT finding_id, json, risk, band FROM scores WHERE run_id = ? "
            "ORDER BY risk DESC, finding_id",
            (run_id,),
        ):
            score = _object(row["json"], f"{self.path}: scores {row['finding_id']}", SCORE_KEYS)
            if any(score[key] != row[key] for key in ("finding_id", "risk", "band")):
                raise ConfigError(f"inconsistent stored score {row['finding_id']} in {self.path}")
            scores.append(score)
        return {
            "run": run,
            "hosts": hosts,
            "findings": findings,
            "context": self._records(
                "SELECT json FROM context_profiles WHERE run_id = ? ORDER BY host_ip",
                run_id,
                "context_profiles",
            ),
            "scores": scores,
            "enrichments": self._records(
                "SELECT e.json FROM enrichments e JOIN finding_runs r "
                "ON r.finding_id = e.finding_id WHERE r.run_id = ? "
                "ORDER BY e.finding_id, e.cve_id",
                run_id,
                "enrichments",
            ),
            "rationales": self._records(
                "SELECT json FROM rationales WHERE run_id = ? ORDER BY finding_id",
                run_id,
                "rationales",
            ),
            "feeds_meta": [
                dict(row)
                for row in self._rows(
                    "SELECT feed, path, sha256, file_date, rows, loaded_at "
                    "FROM feeds_meta ORDER BY feed"
                )
            ],
            "feeds_meta_scope": "current_store_not_frozen_per_run",
            "refusals": self.unavailable("refusal log", run_id),
            "config_hashes": {
                "run_config": run["config_hash"],
                "score_weights": sorted({score["weights_hash"] for score in scores}),
            },
        }


class PostgresReadOnlyStore:
    """PostgreSQL equivalent of the UI reader, restricted to the private schema."""

    def __init__(self, url: str) -> None:
        self.connection: Any
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
            with self.connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION READ ONLY")
                cursor.execute("SET search_path TO vulnassess")
        except Exception as error:
            raise ConfigError("cannot open the configured PostgreSQL assessment store") from error

    def __enter__(self) -> "PostgresReadOnlyStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.connection.close()

    def _rows(self, query: str, parameters: tuple[str, ...] = ()) -> list[dict[str, Any]]:
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, parameters)
                return list(cursor.fetchall())
        except Exception as error:
            raise ConfigError("cannot read PostgreSQL UI records") from error

    @staticmethod
    def _object(value: Any, label: str, keys: frozenset[str] | None = None) -> dict[str, Any]:
        if isinstance(value, dict):
            result = value
        elif isinstance(value, str):
            result = _object(value, label, keys)
            return result
        else:
            raise ConfigError(f"expected a stored JSON object at {label}")
        if keys is not None and set(result) != keys:
            missing = sorted(keys - set(result))
            unknown = sorted(set(result) - keys)
            raise ConfigError(f"stored keys at {label}: missing={missing}; unknown={unknown}")
        return result

    def runs(self) -> list[dict[str, Any]]:
        rows = self._rows(
            "SELECT run_id, started_at::text, config_hash, summary_json FROM runs "
            "ORDER BY started_at DESC, run_id"
        )
        return [
            {
                "run_id": row["run_id"],
                "started_at": row["started_at"],
                "config_hash": row["config_hash"],
                "summary": self._object(row["summary_json"], "runs.summary_json"),
            }
            for row in rows
        ]

    def run_info(self, run_id: str) -> dict[str, Any]:
        rows = self._rows(
            "SELECT run_id, started_at::text, config_hash, summary_json FROM runs WHERE run_id = %s",
            (run_id,),
        )
        if not rows:
            raise ConfigError(f"MISSING: run {run_id!r} in PostgreSQL")
        row = rows[0]
        return {
            "run_id": row["run_id"],
            "started_at": row["started_at"],
            "config_hash": row["config_hash"],
            "summary": self._object(row["summary_json"], "runs.summary_json"),
        }

    def _records(
        self, query: str, run_id: str, label: str, keys: frozenset[str] | None = None
    ) -> list[dict[str, Any]]:
        return [self._object(row["json"], label, keys) for row in self._rows(query, (run_id,))]

    def unavailable(self, record: str, run_id: str) -> dict[str, Any]:
        return {
            "status": "MISSING",
            "records": None,
            "reason": f"MISSING: persisted {record} for run {run_id!r} in PostgreSQL; the viewer does not calculate or create these records",
        }

    def run(self, run_id: str) -> dict[str, Any]:
        run = self.run_info(run_id)
        scores = self._records(
            "SELECT json FROM scores WHERE run_id = %s ORDER BY risk DESC, finding_id",
            run_id,
            "scores",
            SCORE_KEYS,
        )
        return {
            "run": run,
            "hosts": self._records(
                "SELECT json FROM hosts WHERE run_id = %s ORDER BY ip", run_id, "hosts", HOST_KEYS
            ),
            "findings": self._records(
                "SELECT f.json FROM findings f JOIN finding_runs r ON r.finding_id = f.id WHERE r.run_id = %s ORDER BY f.id",
                run_id,
                "findings",
                FINDING_KEYS,
            ),
            "context": self._records(
                "SELECT json FROM context_profiles WHERE run_id = %s ORDER BY host_ip",
                run_id,
                "context_profiles",
            ),
            "scores": scores,
            "enrichments": self._records(
                "SELECT e.json FROM enrichments e JOIN finding_runs r ON r.finding_id = e.finding_id WHERE r.run_id = %s ORDER BY e.finding_id, e.cve_id",
                run_id,
                "enrichments",
            ),
            "rationales": self._records(
                "SELECT json FROM rationales WHERE run_id = %s ORDER BY finding_id",
                run_id,
                "rationales",
            ),
            "feeds_meta": self._rows(
                "SELECT feed, path, sha256, file_date::text, rows, loaded_at::text FROM feeds_meta ORDER BY feed"
            ),
            "feeds_meta_scope": "current_store_not_frozen_per_run",
            "refusals": self.unavailable("refusal log", run_id),
            "config_hashes": {
                "run_config": run["config_hash"],
                "score_weights": sorted({score["weights_hash"] for score in scores}),
            },
        }


def open_read_store(database: str | Path) -> ReadOnlyStore | PostgresReadOnlyStore:
    url = database_url(database)
    return PostgresReadOnlyStore(url) if url is not None else ReadOnlyStore(database)
