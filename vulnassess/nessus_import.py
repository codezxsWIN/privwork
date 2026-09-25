"""Explicit, scope-bound import of a completed Nessus report into a local run."""

import re
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from vulnassess import intel, pipeline
from vulnassess.errors import ConfigError, ScopeError
from vulnassess.readers import parse_nessus_xml
from vulnassess.settings import Settings
from vulnassess.store import Store


def import_nessus_report(
    database: str | Path,
    config_dir: Path,
    run_id: str,
    target_ip: str,
    content: bytes,
    *,
    new_run: bool = False,
) -> dict[str, Any]:
    """Validate one report before writing, then refresh context and deterministic scores."""
    if isinstance(database, str):
        raise ConfigError("Nessus import is available only for a local assessment database")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", run_id):
        raise ConfigError("Invalid assessment run identifier")
    settings = Settings(config_dir)
    if (
        settings.scope.is_canary(target_ip)
        or not settings.scope.contains(target_ip)
        or settings.scope.name(target_ip) is None
    ):
        raise ScopeError("Nessus report target is outside explicitly authorized scope")
    with Store(database) as store:
        existing = store.run_info(run_id)
        if new_run and existing is not None:
            raise ConfigError("Assessment name already exists; choose a new name")
        if not new_run and existing is None:
            raise ConfigError("Select an existing assessment run before importing a report")
        with TemporaryDirectory() as directory:
            digest = sha256(content).hexdigest()[:16]
            path = Path(directory) / f"report-{digest}.nessus"
            path.write_bytes(content)
            parse_nessus_xml(path, run_id, host_ip=target_ip)
            summary = pipeline.do_import(settings, store, run_id, target_ip, None, nessus_path=path)
        enrichment = intel.enrich_run(run_id, store) if store.feeds_meta() else None
        pipeline.do_context(settings, store, run_id)
        scores = pipeline.do_rank(settings, store, run_id)
    return {"import": summary, "enrichment": enrichment, "scores": len(scores), "run_id": run_id}
