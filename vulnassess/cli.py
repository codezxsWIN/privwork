"""Command-line entry points. Every command has --json; run commands need --run-id."""

import argparse
import json
import sys
from datetime import date
from hashlib import sha256
from pathlib import Path
from typing import Any, Sequence

from vulnassess import (
    __version__,
    assessment_snapshot,
    audit,
    cohort,
    context_eval,
    diff,
    evaluate,
    experiments,
    explain,
    intel,
    model_governance,
    orchestrator,
    pipeline,
    rescan,
    role_model,
    unify,
)
from vulnassess.errors import AdapterError, ConfigError, VulnAssessError
from vulnassess.settings import Settings
from vulnassess.store import Store

DEFAULT_DB = "data/vulnassess.db"
DEFAULT_CONFIG = "config"
MAX_COHORT_IDS_BYTES = 1024 * 1024


def _emit(payload: Any, text: str, as_json: bool) -> None:
    print(json.dumps(payload, sort_keys=True, indent=2) if as_json else text)


def _payload_digest(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _write_json_payload(payload: dict[str, Any], output: str | None) -> str | None:
    if output is None:
        return None
    path = Path(output)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(payload, sort_keys=True, indent=2, allow_nan=False) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)
    except OSError as error:
        raise ConfigError(f"cannot write JSON artifact {path}: {error}") from error
    return str(path)


def _iso_date(value: str, label: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise ConfigError(f"{label} must be an ISO date, got {value!r}") from error


def _parse_target(spec: str) -> tuple[str, str, str | None]:
    """IP:nmap[:zap], tolerating Windows drive letters inside the paths."""
    raw = spec.split(":")
    parts: list[str] = []
    index = 0
    while index < len(raw):
        token = raw[index]
        if len(token) == 1 and token.isalpha() and index + 1 < len(raw):
            parts.append(f"{token}:{raw[index + 1]}")
            index += 2
            continue
        parts.append(token)
        index += 1
    if len(parts) < 2:
        raise ConfigError(f"--target {spec!r} must look like IP:nmap.xml[:zap.json]")
    return parts[0], parts[1], parts[2] if len(parts) > 2 else None


def _settings(args: argparse.Namespace) -> Settings:
    return Settings(Path(args.config))


def _store(args: argparse.Namespace) -> Store:
    return Store(args.db)


def _require_artifact_run(actual: Any, expected: str, artifact: str) -> None:
    if str(actual) != expected:
        raise ConfigError(f"{artifact} belongs to run {actual!r}, not requested run {expected!r}")


def _cohort_finding_ids(args: argparse.Namespace, snapshot: dict[str, Any]) -> list[str]:
    if args.all_findings:
        return [str(item["id"]) for item in snapshot["findings"]]
    if args.finding_id:
        return list(args.finding_id)
    path = Path(args.ids_file)
    if not path.is_file():
        raise ConfigError(f"MISSING: cohort finding ID file {path}")
    if path.stat().st_size > MAX_COHORT_IDS_BYTES:
        raise ConfigError(f"cohort finding ID file {path} exceeds {MAX_COHORT_IDS_BYTES} bytes")
    try:
        finding_ids = [
            line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
        ]
    except OSError as error:
        raise ConfigError(f"cannot read cohort finding ID file {path}: {error}") from error
    if not finding_ids:
        raise ConfigError(f"cohort finding ID file {path} is empty")
    return finding_ids


def _load_bound_research_truth(
    args: argparse.Namespace, settings: Settings, store: Store
) -> tuple[cohort.CohortManifest, dict[str, Any]]:
    snapshot = assessment_snapshot.load_snapshot(args.snapshot)
    manifest = cohort.load_manifest(args.manifest)
    _require_artifact_run(snapshot["run"].get("run_id"), args.run_id, "assessment snapshot")
    _require_artifact_run(manifest.run_id, args.run_id, "cohort manifest")
    cohort.validate_snapshot_against_manifest(snapshot, manifest)
    cohort.load_evidence(args.evidence, manifest)
    truth = evaluate.load_truth(args.truth)
    cohort.validate_truth_against_cohort(truth, manifest)
    live_snapshot = assessment_snapshot.build_snapshot(
        settings, store, args.run_id, model_hash=manifest.model_hash
    )
    if live_snapshot["snapshot_hash"] != manifest.snapshot_hash:
        raise ConfigError(
            "live run state no longer matches the cohort assessment snapshot; "
            "use the frozen inputs or create a new cohort"
        )
    return manifest, truth


def cmd_import(args: argparse.Namespace) -> int:
    settings = _settings(args)
    with _store(args) as store:
        summary = pipeline.do_import(
            settings,
            store,
            args.run_id,
            args.target_ip,
            args.nmap,
            args.zap,
            args.nikto,
            args.nessus,
        )
    counts = ", ".join(f"{tool} {count}" for tool, count in sorted(summary["findings"].items()))
    _emit(
        summary,
        f"run {summary['run_id']}: {summary['hosts']} host(s); new findings: {counts or 'none'}",
        args.json,
    )
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    settings = _settings(args)
    tools = args.tool or list(orchestrator.TOOLS)
    scan_plan = orchestrator.plan(
        settings,
        args.target_ip,
        args.out_dir,
        tools=tools,
        canary_log=args.canary_log,
    )
    missing = orchestrator.missing_binaries(tools)
    notice = orchestrator.NOT_RUN_BY_AGENT
    if not args.execute:
        core = {
            "run_id": args.run_id,
            "executed": False,
            "evidence_status": "NOT RUN",
            "notice": notice,
            "plan": scan_plan.to_json(),
            "missing": missing,
            "next_stage": (
                "run Nmap discovery first; only observed HTTP(S) endpoints may produce "
                "Nikto commands"
            ),
        }
        summary = {**core, "summary_hash": _payload_digest(core)}
        output = _write_json_payload(summary, args.summary_out)
        if output is not None:
            summary["summary_output"] = output
        lines = [
            f"{notice}: {' '.join(scan_plan.discovery.argv)}",
            "Nikto commands are deferred until successful Nmap output proves web endpoints.",
        ]
        if missing:
            details = "; ".join(
                f"{tool}: {orchestrator.scanner_status(tool)['detail']}" for tool in missing
            )
            lines.append(f"MISSING scanner requirements: {details}")
        lines.append("Planned only. A human may pass --execute for the authorised lab target.")
        _emit(summary, "\n".join(lines), args.json)
        return 0
    if missing:
        raise ConfigError(f"MISSING scanner binary/binaries {missing}; a human must provision them")

    result = orchestrator.orchestrate(
        scan_plan,
        args.run_id,
        lambda command: orchestrator.execute_local(command, timeout=args.timeout),
    )
    result["run_id"] = args.run_id
    result["executed"] = True
    result["evidence_status"] = "VERIFIED"
    result["notice"] = notice
    result["canary_evidence_after"] = orchestrator.check_canary_log(args.canary_log)
    core = dict(result)
    result["summary_hash"] = _payload_digest(core)
    output = _write_json_payload(result, args.summary_out)
    if output is not None:
        result["summary_output"] = output
    with _store(args) as store:
        store.start_run(args.run_id, settings.config_hash())
        existing = (store.run_info(args.run_id) or {}).get("summary") or {}
        store.set_run_summary(
            args.run_id,
            {**existing, "scans": [*existing.get("scans", []), result]},
        )
        for outcome in result["outcomes"]:
            if outcome["status"] != "success":
                continue
            tool = outcome["tool"]
            raw_path = outcome["raw_path"]
            pipeline.do_import(
                settings,
                store,
                args.run_id,
                args.target_ip,
                nmap_path=raw_path if tool == "nmap" else None,
                zap_path=raw_path if tool == "zap" else None,
                nikto_path=raw_path if tool == "nikto" else None,
            )
    _emit(
        result,
        f"scan outcomes: success={result['successful_tools']} failed={result['failed_tools']} "
        f"skipped={result['skipped_tools']}; {notice}",
        args.json,
    )
    return 0 if result["complete"] else AdapterError.exit_code


def cmd_research_snapshot_export(args: argparse.Namespace) -> int:
    settings = _settings(args)
    model_hash = None
    if args.model_artifact:
        model_hash = role_model.load_model(args.model_artifact).model_hash
    with _store(args) as store:
        payload = assessment_snapshot.build_snapshot(
            settings, store, args.run_id, model_hash=model_hash
        )
    path = assessment_snapshot.save_snapshot(payload, args.out)
    result = {
        "run_id": args.run_id,
        "path": str(path),
        "snapshot_hash": payload["snapshot_hash"],
        "findings": len(payload["findings"]),
        "hosts": len(payload["hosts"]),
        "config_drift": payload["configuration"]["drift"],
        "model_hash": model_hash,
    }
    _emit(
        result,
        f"snapshot {payload['snapshot_hash']} for run {args.run_id}: "
        f"{result['hosts']} hosts, {result['findings']} findings -> {path}",
        args.json,
    )
    return 0


def cmd_research_snapshot_verify(args: argparse.Namespace) -> int:
    payload = assessment_snapshot.load_snapshot(args.snapshot)
    _require_artifact_run(payload["run"].get("run_id"), args.run_id, "assessment snapshot")
    result = {
        "run_id": args.run_id,
        "path": str(Path(args.snapshot)),
        "snapshot_hash": payload["snapshot_hash"],
        "findings": len(payload["findings"]),
        "hosts": len(payload["hosts"]),
        "verification": "VERIFIED",
    }
    _emit(
        result,
        f"VERIFIED snapshot hash {payload['snapshot_hash']} for run {args.run_id}",
        args.json,
    )
    return 0


def cmd_research_cohort_freeze(args: argparse.Namespace) -> int:
    snapshot = assessment_snapshot.load_snapshot(args.snapshot)
    _require_artifact_run(snapshot["run"].get("run_id"), args.run_id, "assessment snapshot")
    finding_ids = _cohort_finding_ids(args, snapshot)
    manifest, items = cohort.freeze_cohort(
        snapshot,
        finding_ids,
        cohort_id=args.cohort_id,
        created_on=args.created_on,
        evidence_status=args.evidence_status,
        reviewer=args.reviewer,
        approval_id=args.approval_id,
    )
    output = cohort.save_cohort(manifest, items, args.out_dir)
    result = {
        "run_id": args.run_id,
        "cohort_id": manifest.cohort_id,
        "cohort_hash": manifest.manifest_hash,
        "evidence_status": manifest.evidence_status,
        "findings": len(items),
        "path": str(output),
        "finding_mode": manifest.finding_mode,
    }
    _emit(
        result,
        f"frozen {manifest.evidence_status} cohort {manifest.cohort_id} "
        f"({len(items)} raw findings) at {output}; hash {manifest.manifest_hash}",
        args.json,
    )
    return 0


def cmd_research_cohort_verify(args: argparse.Namespace) -> int:
    manifest = cohort.load_manifest(args.manifest)
    _require_artifact_run(manifest.run_id, args.run_id, "cohort manifest")
    items = cohort.load_evidence(args.evidence, manifest)
    truth_validated = False
    if args.truth:
        truth = evaluate.load_truth(args.truth)
        cohort.validate_truth_against_cohort(truth, manifest)
        truth_validated = True
    result = {
        "run_id": args.run_id,
        "cohort_id": manifest.cohort_id,
        "cohort_hash": manifest.manifest_hash,
        "evidence_status": manifest.evidence_status,
        "findings": len(items),
        "evidence_verified": True,
        "truth_validated": truth_validated,
    }
    truth_text = " and expert truth covers it exactly" if truth_validated else ""
    _emit(
        result,
        f"VERIFIED cohort {manifest.cohort_id} hash and {len(items)} evidence items{truth_text}",
        args.json,
    )
    return 0


def cmd_research_context_eval(args: argparse.Namespace) -> int:
    truth = context_eval.load_context_truth(args.truth)
    model = role_model.load_model(args.model_artifact) if args.model_artifact else None
    with _store(args) as store:
        if store.run_info(args.run_id) is None:
            raise ConfigError(f"MISSING: run {args.run_id!r}")
        profiles = store.profiles(args.run_id)
        predictions = (
            None
            if model is None
            else {host.ip: model.predict(host) for host in store.hosts(args.run_id)}
        )
    result = context_eval.evaluate_context(profiles, truth, predictions)
    result["run_id"] = args.run_id
    result["model_hash"] = None if model is None else model.model_hash
    result["evaluation_hash"] = _payload_digest(result)
    output = _write_json_payload(result, args.out)
    if output is not None:
        result["output"] = output
    role = result["rule_role"]
    exposure = result["exposure"]
    _emit(
        result,
        f"{result['status']} RQ1 evaluation: role accuracy={role['accuracy']} "
        f"coverage={role['coverage']}; exposure accuracy={exposure['accuracy']}; "
        f"H1 eligible={result['h1']['eligible']}",
        args.json,
    )
    return 0


def cmd_research_ranking_eval(args: argparse.Namespace) -> int:
    settings = _settings(args)
    with _store(args) as store:
        manifest, truth = _load_bound_research_truth(args, settings, store)
        cohort_ids = set(manifest.finding_ids)
        methods = {
            name: [finding_id for finding_id in order if finding_id in cohort_ids]
            for name, order in pipeline.baseline_orders(store, args.run_id).items()
        }
    result = evaluate.evaluate(methods, truth)
    result["run_id"] = args.run_id
    result["cohort_id"] = manifest.cohort_id
    result["cohort_hash"] = manifest.manifest_hash
    result["snapshot_hash"] = manifest.snapshot_hash
    result["evaluation_hash"] = _payload_digest(result)
    output = _write_json_payload(result, args.out)
    if output is not None:
        result["output"] = output
    _emit(result, evaluate.markdown_table(result), args.json)
    return 0


def cmd_research_ablate(args: argparse.Namespace) -> int:
    settings = _settings(args)
    bundle_values = (args.snapshot, args.manifest, args.evidence, args.truth)
    if any(bundle_values) and not all(bundle_values):
        raise ConfigError(
            "expert ablation needs --snapshot, --manifest, --evidence, and --truth together"
        )
    with _store(args) as store:
        manifest = None
        truth = None
        if all(bundle_values):
            manifest, truth = _load_bound_research_truth(args, settings, store)
        result = experiments.run_ablations(
            settings,
            store,
            args.run_id,
            scenarios=args.scenario or experiments.SCENARIOS,
            truth=truth,
            cohort_ids=None if manifest is None else manifest.finding_ids,
            research_binding=(
                None
                if manifest is None
                else {
                    "cohort_id": manifest.cohort_id,
                    "cohort_hash": manifest.manifest_hash,
                    "snapshot_hash": manifest.snapshot_hash,
                }
            ),
        )
    output = _write_json_payload(result, args.out)
    if output is not None:
        result["output"] = output
    lines = [
        f"{name}: changed={comparison['changed_findings']} "
        f"bands={comparison['band_changes']} inactive={comparison['inactive']}"
        for name, comparison in result["comparisons"].items()
    ]
    lines.append(f"experiment hash {result['experiment_hash']}")
    _emit(result, "\n".join(lines), args.json)
    return 0


def cmd_research_stability(args: argparse.Namespace) -> int:
    settings = _settings(args)
    snapshot = assessment_snapshot.load_snapshot(args.snapshot)
    _require_artifact_run(snapshot["run"].get("run_id"), args.run_id, "assessment snapshot")
    with _store(args) as store:
        live_snapshot = assessment_snapshot.build_snapshot(
            settings,
            store,
            args.run_id,
            model_hash=snapshot.get("model_hash"),
        )
        if live_snapshot["snapshot_hash"] != snapshot["snapshot_hash"]:
            raise ConfigError("live run state no longer matches the supplied assessment snapshot")
        result = experiments.stability_check(settings, store, args.run_id, repeats=args.repeats)
    result["snapshot_hash"] = snapshot["snapshot_hash"]
    result["input_evidence_status"] = snapshot["evidence_status"]
    result["evidence_status"] = "VERIFIED"
    result["stability_hash"] = _payload_digest(result)
    output = _write_json_payload(result, args.out)
    if output is not None:
        result["output"] = output
    _emit(
        result,
        f"{'VERIFIED' if result['deterministic'] else 'FAILED'}: "
        f"{result['unique_score_hashes']} unique score hashes across "
        f"{result['repeats']} repeats",
        args.json,
    )
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    client = None if args.no_model else explain.OllamaClient(args.ollama_host, args.model)
    with _store(args) as store:
        counts = explain.explain_run(args.run_id, store, client)
    _emit(
        counts,
        f"{counts['llm']} sentence(s) from the model, {counts['template']} deterministic",
        args.json,
    )
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    with _store(args) as store:
        result = diff.diff_runs(store, args.before, args.after)
    _emit(result, diff.markdown_table(result), args.json)
    return 0


def cmd_unify_preview(args: argparse.Namespace) -> int:
    settings = _settings(args)
    snapshot = assessment_snapshot.load_snapshot(args.snapshot)
    _require_artifact_run(snapshot["run"].get("run_id"), args.run_id, "assessment snapshot")
    with _store(args) as store:
        live_snapshot = assessment_snapshot.build_snapshot(
            settings,
            store,
            args.run_id,
            model_hash=snapshot.get("model_hash"),
        )
        if live_snapshot["snapshot_hash"] != snapshot["snapshot_hash"]:
            raise ConfigError("live run state no longer matches the supplied assessment snapshot")
        result = unify.unify_run(store, args.run_id).to_json()
    core = {
        "run_id": args.run_id,
        "snapshot_hash": snapshot["snapshot_hash"],
        "evidence_status": snapshot["evidence_status"],
        "data_kind": "assessment_diagnostic",
        "mode": "preview_only",
        "downstream_ranking_changed": False,
        **result,
    }
    payload = {**core, "preview_hash": _payload_digest(core)}
    output = _write_json_payload(payload, args.out)
    if output is not None:
        payload["output"] = output
    _emit(
        payload,
        f"unification preview: {result['raw_count']} raw -> "
        f"{result['unified_count']} groups; {len(result['candidates'])} review candidates; "
        "ranking remains raw",
        args.json,
    )
    return 0


def cmd_rescan_compare(args: argparse.Namespace) -> int:
    before = rescan.load_observation_artifact(args.before)
    after = rescan.load_observation_artifact(args.after)
    _require_artifact_run(after.observation.run_id, args.run_id, "after observation")
    payload = rescan.compare_runs(
        before.observation,
        after.observation,
        before_scores=before.scores,
        after_scores=after.scores,
    )
    statuses = (before.evidence_status, after.evidence_status)
    if "MISSING" in statuses:
        evidence_status = "MISSING"
    elif statuses == ("VERIFIED", "VERIFIED"):
        evidence_status = "VERIFIED"
    elif "NOT RUN" in statuses:
        evidence_status = "NOT RUN"
    else:
        evidence_status = "TESTED WITH MOCKS"
    payload["evidence_status"] = evidence_status
    payload["observation_hashes"] = {
        "before": before.artifact_hash,
        "after": after.artifact_hash,
    }
    core = dict(payload)
    payload["comparison_hash"] = _payload_digest(core)
    output = _write_json_payload(payload, args.out)
    if output is not None:
        payload["output"] = output
    counts = payload["counts"]
    _emit(
        payload,
        f"{evidence_status} re-scan preview: still_open={counts['still_open']} "
        f"fixed_candidate={counts['fixed_candidate']} "
        f"not_observable={counts['not_observable']} "
        f"new={counts['new_finding']} regression_candidate={counts['regression_candidate']}",
        args.json,
    )
    return 0


def cmd_model_validate_promotion(args: argparse.Namespace) -> int:
    model = role_model.load_model(args.model_artifact)
    manifest = model_governance.load_manifest(args.manifest)
    result = model_governance.validate_promotion(
        model, manifest, as_of=_iso_date(args.as_of, "--as-of")
    )
    result["canonical_context_changed"] = False
    result["notice"] = (
        "validation authorizes recommendations only; model-derived context remains blocked "
        "without the approved context-source ADR"
    )
    _emit(
        result,
        f"promotion manifest valid for model {model.model_hash}; "
        "canonical context remains unchanged",
        args.json,
    )
    return 0


def cmd_model_hybrid_preview(args: argparse.Namespace) -> int:
    as_of = _iso_date(args.as_of, "--as-of")
    model = role_model.load_model(args.model_artifact)
    manifest = model_governance.load_manifest(args.manifest)
    model_governance.validate_promotion(model, manifest, as_of=as_of)
    with _store(args) as store:
        if store.run_info(args.run_id) is None:
            raise ConfigError(f"MISSING: run {args.run_id!r}")
        profiles = {profile.host_ip: profile for profile in store.profiles(args.run_id)}
        recommendations = []
        for host in store.hosts(args.run_id):
            profile = profiles.get(host.ip)
            if profile is None:
                raise ConfigError(
                    f"MISSING: context profile for host {host.ip!r} in run {args.run_id!r}"
                )
            prediction = model.predict(host)
            recommendation = model_governance.recommend_hybrid_role(
                profile.role,
                prediction,
                model,
                manifest,
                as_of=as_of,
            )
            recommendations.append(
                {
                    "host_ip": host.ip,
                    "prediction": prediction.to_json(),
                    "recommendation": recommendation.to_json(),
                }
            )
    result = {
        "run_id": args.run_id,
        "model_hash": model.model_hash,
        "manifest_approval_id": manifest.approval_id,
        "as_of": as_of.isoformat(),
        "canonical_context_changed": False,
        "recommendations": recommendations,
        "notice": "SHADOW ONLY: recommendations were not written and cannot change ranks",
    }
    _emit(
        result,
        "\n".join(
            f"{item['host_ip']}: {item['recommendation']['action']} -> "
            f"{item['recommendation']['selected_label']} "
            f"({item['recommendation']['selected_source']})"
            for item in recommendations
        )
        + "\nSHADOW ONLY: canonical context and ranks are unchanged",
        args.json,
    )
    return 0


def _reject_synthetic_labels(examples: Sequence[role_model.LabelledHost], allowed: bool) -> None:
    synthetic = sum(example.label_source == "synthetic" for example in examples)
    if synthetic and not allowed:
        raise ConfigError(
            f"dataset contains {synthetic} synthetic label(s); training on them requires "
            "--allow-synthetic and cannot establish model validity"
        )


def _training_options(args: argparse.Namespace) -> dict[str, Any]:
    families = getattr(args, "families", None)
    return {
        "epochs": args.epochs,
        "learning_rate": args.learning_rate,
        "l2": args.l2,
        "min_feature_count": args.min_feature_count,
        "feature_families": (
            None
            if not families
            else [family.strip() for family in families.split(",") if family.strip()]
        ),
    }


def cmd_model_labels(args: argparse.Namespace) -> int:
    with _store(args) as store:
        hosts = store.hosts(args.run_id)
    if not hosts:
        raise ConfigError(f"MISSING: hosts for run {args.run_id!r}")
    path = role_model.export_label_template(hosts, args.run_id, args.out)
    payload = {"run_id": args.run_id, "hosts": len(hosts), "path": str(path)}
    _emit(payload, f"wrote {len(hosts)} unlabeled host(s) to {path}", args.json)
    return 0


def cmd_model_train(args: argparse.Namespace) -> int:
    examples = role_model.load_examples(args.data)
    _reject_synthetic_labels(examples, args.allow_synthetic)
    model = role_model.train(examples, **_training_options(args))
    validation_metrics = None
    if args.validation:
        validation = role_model.load_examples(args.validation)
        _reject_synthetic_labels(validation, args.allow_synthetic)
        overlap = sorted({item.group for item in examples} & {item.group for item in validation})
        if overlap:
            raise ConfigError(
                f"training/validation group leakage: {overlap[:5]}; use independent hosts"
            )
        model = role_model.calibrate(model, validation)
        validation_metrics = role_model.evaluate(model, validation)
    path = role_model.save_model(model, args.out)
    payload = {
        "path": str(path),
        "model_hash": model.model_hash,
        "classes": list(model.classes),
        "features": len(model.features),
        "training": model.training,
        "validation": validation_metrics,
    }
    if getattr(args, "register", False):
        payload["registered"] = _register_role_model_run(args, model, examples, validation_metrics)
        payload["registered_dataset"] = args.dataset_name
    text = (
        f"model {model.model_hash}: {len(model.classes)} classes, "
        f"{len(model.features)} features; written to {path}"
    )
    if validation_metrics:
        text += (
            f"; validation accuracy={validation_metrics['accuracy']:.3f} "
            f"coverage={validation_metrics['coverage']:.3f} "
            f"macro_f1={validation_metrics['macro_f1']:.3f}"
        )
    else:
        text += "; NOT VALIDATED (no independent --validation dataset)"
    if payload.get("registered"):
        text += f"; registered as {payload['registered']}"
    _emit(payload, text, args.json)
    return 0


def _register_role_model_run(
    args: argparse.Namespace,
    model: role_model.RoleModel,
    examples: Sequence[role_model.LabelledHost],
    validation_metrics: dict[str, Any] | None,
) -> str:
    """Record the training run in the assessment store for reproducibility."""
    from vulnassess.repository import AssessmentRepository, resolve_backend

    if not (args.dataset_name or "").strip():
        raise ConfigError("--register needs --dataset-name")
    options = _training_options(args)
    config_payload = json.dumps(options, sort_keys=True, separators=(",", ":"))
    config_hash = sha256(config_payload.encode("utf-8")).hexdigest()[:16]
    data_kind = (
        "synthetic"
        if any(example.label_source == "synthetic" for example in examples)
        else "real_authorised"
    )
    reviewers = sorted({example.reviewer for example in examples if example.reviewer})
    database = getattr(args, "db", None)
    with AssessmentRepository(resolve_backend(database if database else None)) as repository:
        dataset_id = repository.add_dataset(
            {
                "name": args.dataset_name.strip(),
                "version": (args.dataset_version or "1").strip(),
                "source": "vulnassess model train CLI",
                "data_kind": data_kind,
                "reviewer": reviewers[0] if reviewers else None,
                "quality": "draft",
                "config_hash": config_hash,
                "content_sha256": role_model.dataset_hash(examples),
                "row_count": len(examples),
            }
        )
        split: dict[str, Any] = {"train_groups": model.training["groups"]}
        if validation_metrics:
            split["validation_groups"] = validation_metrics["groups"]
        notes = f"artifact={args.out}; families={model.training['feature_families']}"
        if not validation_metrics:
            notes += "; not validated (no independent validation set)"
        return repository.add_role_model_run(
            {
                "dataset_id": dataset_id,
                "model_name": "vulnassess-role-model",
                "model_hash": model.model_hash,
                "label_set": list(model.classes),
                "split": split,
                "accuracy": None if validation_metrics is None else validation_metrics["accuracy"],
                "macro_f1": (
                    None if validation_metrics is None else validation_metrics["macro_f1"]
                ),
                "per_class": (
                    {} if validation_metrics is None else validation_metrics["per_class"]
                ),
                "coverage": (
                    None if validation_metrics is None else validation_metrics["coverage"]
                ),
                "abstention_rate": (
                    None if validation_metrics is None else validation_metrics["abstention_rate"]
                ),
                "confusion": (
                    {} if validation_metrics is None else validation_metrics["confusion_matrix"]
                ),
                "notes": notes,
            }
        )


def cmd_model_ablate(args: argparse.Namespace) -> int:
    examples = role_model.load_examples(args.data)
    _reject_synthetic_labels(examples, args.allow_synthetic)
    options = _training_options(args)
    families = options.pop("feature_families")
    if families is not None and args.subsets:
        raise ConfigError("model ablate accepts --families or --subsets, not both")
    subsets = None
    if args.subsets:
        subsets = [
            None
            if subset.strip() == "all"
            else [family.strip() for family in subset.split(",") if family.strip()]
            for subset in args.subsets.split(";")
        ]
    elif families is not None:
        subsets = [families]
    result = role_model.ablate_features(examples, folds=args.folds, subsets=subsets, **options)
    lines = [f"feature-family ablation over {result['examples']} labelled host(s):"]
    for entry in result["results"]:
        aggregate = entry["aggregate"]
        lines.append(
            f"  {entry['subset']:<28} accuracy={aggregate['accuracy']:.3f} "
            f"macro_f1={aggregate['macro_f1']:.3f} "
            f"coverage={aggregate['coverage']:.3f} "
            f"abstention={aggregate['abstention_rate']:.3f}"
        )
    lines.append(
        "Compare subsets on the same group folds; a large drop without banners or "
        "products means the model relies on vendor shortcuts rather than structure."
    )
    _emit(result, "\n".join(lines), args.json)
    return 0


def cmd_model_cross_validate(args: argparse.Namespace) -> int:
    examples = role_model.load_examples(args.data)
    _reject_synthetic_labels(examples, args.allow_synthetic)
    result = role_model.cross_validate(examples, folds=args.folds, **_training_options(args))
    aggregate = result["aggregate"]
    text = (
        f"{result['folds']}-fold grouped CV: accuracy={aggregate['accuracy']:.3f} "
        f"coverage={aggregate['coverage']:.3f} macro_f1={aggregate['macro_f1']:.3f} "
        f"log_loss={aggregate['log_loss']:.3f}"
    )
    _emit(result, text, args.json)
    return 0


def cmd_model_evaluate(args: argparse.Namespace) -> int:
    model = role_model.load_model(args.model_artifact)
    examples = role_model.load_examples(args.data)
    result = role_model.evaluate(model, examples)
    text = (
        f"model {model.model_hash}: accuracy={result['accuracy']:.3f} "
        f"coverage={result['coverage']:.3f} selective_accuracy="
        f"{result['selective_accuracy']} macro_f1={result['macro_f1']:.3f} "
        f"ECE={result['expected_calibration_error']:.3f}"
    )
    _emit(result, text, args.json)
    return 0


def cmd_model_predict(args: argparse.Namespace) -> int:
    model = role_model.load_model(args.model_artifact)
    with _store(args) as store:
        hosts = store.hosts(args.run_id)
    if not hosts:
        raise ConfigError(f"MISSING: hosts for run {args.run_id!r}")
    predictions = [{"host_ip": host.ip, **model.predict(host).to_json()} for host in hosts]
    lines = [
        f"{item['host_ip']}: {item['label']} confidence={item['confidence']:.3f} "
        f"margin={item['margin']:.3f}{' ABSTAINED' if item['abstained'] else ''}; "
        f"evidence: {item['evidence']}"
        for item in predictions
    ]
    lines.append("SHADOW ONLY: predictions were not written to context and cannot change ranks")
    _emit(predictions, "\n".join(lines), args.json)
    return 0


def cmd_model_inspect(args: argparse.Namespace) -> int:
    model = role_model.load_model(args.model_artifact)
    top: dict[str, list[dict[str, Any]]] = {}
    for class_index, label in enumerate(model.classes):
        weighted = sorted(
            zip(model.features, model.coefficients[class_index], strict=True),
            key=lambda item: (-item[1], item[0]),
        )[: args.top]
        top[label] = [
            {"feature": feature, "weight": round(weight, 6)} for feature, weight in weighted
        ]
    payload = {**model.to_json(), "top_positive_features": top}
    lines = [
        f"model {model.model_hash} task={model.task} classes={len(model.classes)} "
        f"features={len(model.features)} temperature={model.temperature}"
    ]
    for label in model.classes:
        summary = ", ".join(f"{item['feature']}={item['weight']:+.3f}" for item in top[label])
        lines.append(f"  {label}: {summary}")
    _emit(payload, "\n".join(lines), args.json)
    return 0


def cmd_visualize(args: argparse.Namespace) -> int:
    from vulnassess.ui.export import export_html
    from vulnassess.ui.server import UiApplication

    application = UiApplication(args.db, args.config, args.run_id)
    output = export_html(application, args.out)
    result = {
        "run_id": args.run_id,
        "output": str(output),
        "read_only": True,
        "interface": "canonical_workbench",
    }
    _emit(
        result,
        f"canonical workbench export for {args.run_id} -> {output}",
        args.json,
    )
    return 0


def cmd_intel_load(args: argparse.Namespace) -> int:
    with _store(args) as store:
        counts = intel.load_feeds(args.from_dir, store)
    _emit(
        counts,
        "loaded " + ", ".join(f"{feed} {count}" for feed, count in sorted(counts.items())),
        args.json,
    )
    return 0


def cmd_intel_status(args: argparse.Namespace) -> int:
    with _store(args) as store:
        meta = store.feeds_meta()
    if not meta:
        _emit(
            {},
            "no feed snapshots loaded; run: vulnassess intel load --from-dir <dir>",
            args.json,
        )
        return 0
    lines = [
        f"{feed:5} date {info['file_date'] or '-':10} rows {info['rows']:>7} "
        f"sha256 {info['sha256'][:16]}"
        for feed, info in sorted(meta.items())
    ]
    _emit(meta, "\n".join(lines), args.json)
    return 0


def cmd_enrich(args: argparse.Namespace) -> int:
    with _store(args) as store:
        counts = intel.enrich_run(args.run_id, store)
    _emit(
        counts,
        f"{counts['matched']}/{counts['findings']} findings matched; "
        f"{counts['enrichments']} enrichment(s)",
        args.json,
    )
    return 0


def cmd_context(args: argparse.Namespace) -> int:
    settings = _settings(args)
    with _store(args) as store:
        profiles = pipeline.do_context(settings, store, args.run_id, args.model_artifact)
    lines = []
    for profile in profiles:
        controls = ", ".join(
            f"{key}={value.value}" for key, value in sorted(profile.controls.items())
        )
        lines.append(
            f"{profile.host_ip}: role={profile.role.value} ({profile.role.confidence:.2f}) "
            f"exposure={profile.exposure.value} ({profile.exposure.confidence:.2f})"
        )
        lines.append(f"    evidence: {profile.role.evidence}")
        lines.append(f"    controls: {controls}")
    _emit([profile.to_json() for profile in profiles], "\n".join(lines), args.json)
    return 0


def cmd_rank(args: argparse.Namespace) -> int:
    settings = _settings(args)
    with _store(args) as store:
        scores = pipeline.do_rank(settings, store, args.run_id)
    limit = args.top if getattr(args, "top", None) else len(scores)
    lines = []
    for position, item in enumerate(scores[:limit], start=1):
        lines.append(
            f"{position:>3} {item.risk:>6} {item.band:<8} {item.host_ip:<15} "
            f"{(item.cve_id or '-'):<16} base {str(item.base_score or '-'):<5} "
            f"env {str(item.env_score or '-'):<5} {item.reason}"
        )
    _emit([item.to_json() for item in scores], "\n".join(lines), args.json)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    settings = _settings(args)
    with _store(args) as store:
        audit_data = audit.collect_report_audit(
            settings,
            store,
            args.run_id,
            snapshot_path=args.snapshot,
            cohort_manifest_path=args.cohort_manifest,
            cohort_evidence_path=args.cohort_evidence,
            artifact_paths={
                "scan": args.scan_artifact,
                "context": args.context_artifact,
                "ranking": args.ranking_artifact,
                "ablation": args.ablation_artifact,
                "stability": args.stability_artifact,
                "unification": args.unification_artifact,
                "rescan": args.rescan_artifact,
            },
            model_path=args.model_artifact,
        )
        path = pipeline.do_report(settings, store, args.run_id, args.out, audit_data=audit_data)
    _emit({"report": str(path)}, f"report written to {path}", args.json)
    return 0


def _live_ranking() -> list[Any]:
    print("Paste one rank per line (space-separated ids share a rank). Blank line ends input.")
    order: list[Any] = []
    for line in sys.stdin:
        line = line.strip()
        if not line:
            break
        ids = line.split()
        order.append(ids if len(ids) > 1 else ids[0])
    return order


def cmd_eval(args: argparse.Namespace) -> int:
    with _store(args) as store:
        if args.live:
            truth = {
                "experts": [{"name": "live", "ranking": _live_ranking()}],
                "expert_critical": [],
            }
            result = evaluate.evaluate(pipeline.baseline_orders(store, args.run_id), truth)
        else:
            if not args.truth:
                raise ConfigError("eval needs --truth <path> or --live")
            result = pipeline.do_eval(store, args.run_id, args.truth)
    _emit(result, evaluate.markdown_table(result), args.json)
    return 0


def cmd_two_machine(args: argparse.Namespace) -> int:
    with _store(args) as store:
        text = pipeline.two_machine_table(store, args.run_id, args.cve)
    _emit({"two_machine": text}, text, args.json)
    return 0


def cmd_ui(args: argparse.Namespace) -> int:
    from vulnassess.ui.server import UiApplication, UiServer

    application = UiApplication(
        args.db, args.config, args.run_id, args.analyst_model, args.ollama_host
    )
    if args.export is not None:
        from vulnassess.ui.export import export_html

        path = export_html(application, args.export)
        _emit(
            {"path": str(path), "run_id": args.run_id, "read_only": True},
            f"UI export: {path}",
            args.json,
        )
        return 0
    with UiServer(application, port=args.port) as server:
        url = f"http://127.0.0.1:{server.server_port}/"
        _emit(
            {"url": url, "run_id": args.run_id, "read_only": False},
            f"VulnAssess: {url}\nLocal workbench. Press Ctrl-C to stop.",
            args.json,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            return 0
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    settings = _settings(args)
    run_id = args.run_id
    with _store(args) as store:
        for spec in args.target:
            target_ip, nmap_path, zap_path = _parse_target(spec)
            summary = pipeline.do_import(settings, store, run_id, target_ip, nmap_path, zap_path)
            counts = ", ".join(
                f"{tool} {count}" for tool, count in sorted(summary["findings"].items())
            )
            print(f"import {target_ip}: {summary['hosts']} host(s); new findings: {counts}")

        loaded = intel.load_feeds(args.feeds, store)
        print("intel: " + ", ".join(f"{feed} {count}" for feed, count in sorted(loaded.items())))
        matched = intel.enrich_run(run_id, store)
        print(f"enrich: {matched['matched']}/{matched['findings']} findings matched")

        profiles = pipeline.do_context(settings, store, run_id)
        for profile in profiles:
            print(
                f"context {profile.host_ip}: role={profile.role.value} "
                f"({profile.role.confidence:.2f}) exposure={profile.exposure.value}"
            )

        scores = pipeline.do_rank(settings, store, run_id)
        print("\nTop findings")
        for position, item in enumerate(scores[:10], start=1):
            print(f"{position:>3} {item.risk:>6} {item.band:<8} {item.host_ip:<15} {item.reason}")

        path = pipeline.do_report(settings, store, run_id, args.out)
        print(f"\nreport: {path}")

        if args.truth:
            result = pipeline.do_eval(store, run_id, args.truth)
            print("\n" + evaluate.markdown_table(result))

        print("\ntwo-machine comparison")
        print(pipeline.two_machine_table(store, run_id))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnassess",
        description="Local-first vulnerability prioritisation for authorised lab targets only.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="configuration directory")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite store path")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add(name: str, handler, run_id: bool = True, **kwargs) -> argparse.ArgumentParser:
        sub = subparsers.add_parser(name, **kwargs)
        sub.add_argument("--json", action="store_true", help="emit JSON")
        if run_id:
            sub.add_argument("--run-id", required=True, help="run identifier")
        sub.set_defaults(handler=handler)
        return sub

    viewer = add(
        "ui", cmd_ui, run_id=False, help="view assessments and import Nessus reports on loopback"
    )
    viewer.add_argument("--run", "--run-id", dest="run_id", help="initial run identifier")
    viewer.add_argument("--port", type=int, default=8765, help="loopback HTTP port")
    viewer.add_argument("--db", default=argparse.SUPPRESS, help="existing SQLite store path")
    viewer.add_argument("--config", default=argparse.SUPPRESS, help="configuration directory")
    viewer.add_argument(
        "--model",
        dest="analyst_model",
        default="llama3.2:3b",
        help="local Ollama model used by the explicit Analyze target action",
    )
    viewer.add_argument("--ollama-host", default="http://127.0.0.1:11434")
    viewer.add_argument(
        "--export", metavar="PATH", help="write one offline HTML file without starting a server"
    )

    importer = add("import", cmd_import, help="import existing scanner output for one target")
    importer.add_argument("--target-ip", required=True)
    importer.add_argument("--nmap", help="optional Nmap XML for observed services")
    importer.add_argument("--zap")
    importer.add_argument("--nikto")
    importer.add_argument("--nessus", help="completed .nessus XML scan export for this target")

    scanner = add("scan", cmd_scan, help="plan Nmap-first scanning for one authorised lab target")
    scanner.add_argument("--target-ip", required=True)
    scanner.add_argument("--tool", action="append", default=None, choices=orchestrator.TOOLS)
    scanner.add_argument("--out-dir", default="data/captures")
    scanner.add_argument("--canary-log")
    scanner.add_argument("--timeout", type=float, default=1800.0)
    scanner.add_argument("--summary-out")
    scanner.add_argument(
        "--execute",
        action="store_true",
        help="human-only: execute against the authorised lab target",
    )

    intel_parser = subparsers.add_parser("intel", help="offline feed snapshots")
    intel_sub = intel_parser.add_subparsers(dest="intel_command", required=True)
    load = intel_sub.add_parser("load", help="load NVD/EPSS/KEV snapshots from a directory")
    load.add_argument("--json", action="store_true")
    load.add_argument("--from-dir", required=True, dest="from_dir")
    load.set_defaults(handler=cmd_intel_load)
    status = intel_sub.add_parser("status", help="show the loaded snapshots")
    status.add_argument("--json", action="store_true")
    status.set_defaults(handler=cmd_intel_status)

    research_parser = subparsers.add_parser(
        "research", help="freeze and evaluate reproducible research artifacts"
    )
    research_sub = research_parser.add_subparsers(dest="research_command", required=True)

    def add_research(name: str, handler, **kwargs) -> argparse.ArgumentParser:
        command = research_sub.add_parser(name, **kwargs)
        command.add_argument("--json", action="store_true", help="emit JSON")
        command.add_argument("--run-id", required=True, help="run identifier")
        command.set_defaults(handler=handler)
        return command

    snapshot_export = add_research(
        "snapshot-export",
        cmd_research_snapshot_export,
        help="export a hash-verified assessment snapshot",
    )
    snapshot_export.add_argument("--out", required=True)
    snapshot_export.add_argument("--model", dest="model_artifact")

    snapshot_verify = add_research(
        "snapshot-verify",
        cmd_research_snapshot_verify,
        help="verify a frozen assessment snapshot",
    )
    snapshot_verify.add_argument("--snapshot", required=True)

    cohort_freeze = add_research(
        "cohort-freeze",
        cmd_research_cohort_freeze,
        help="freeze a blind expert-review cohort from a snapshot",
    )
    cohort_freeze.add_argument("--snapshot", required=True)
    cohort_freeze.add_argument("--cohort-id", required=True)
    cohort_freeze.add_argument("--created-on", required=True, help="human-supplied ISO date")
    cohort_freeze.add_argument("--evidence-status", choices=("VERIFIED", "NOT RUN"), required=True)
    cohort_freeze.add_argument("--reviewer")
    cohort_freeze.add_argument("--approval-id")
    cohort_freeze.add_argument("--out-dir", required=True)
    selection = cohort_freeze.add_mutually_exclusive_group(required=True)
    selection.add_argument("--finding-id", action="append")
    selection.add_argument("--ids-file")
    selection.add_argument("--all-findings", action="store_true")

    cohort_verify = add_research(
        "cohort-verify",
        cmd_research_cohort_verify,
        help="verify frozen cohort evidence and optional expert truth",
    )
    cohort_verify.add_argument("--manifest", required=True)
    cohort_verify.add_argument("--evidence", required=True)
    cohort_verify.add_argument("--truth")

    context_evaluator = add_research(
        "context-eval",
        cmd_research_context_eval,
        help="evaluate rule context and optional shadow-model roles",
    )
    context_evaluator.add_argument("--truth", required=True)
    context_evaluator.add_argument("--model", dest="model_artifact")
    context_evaluator.add_argument("--out")

    ranking_evaluator = add_research(
        "ranking-eval",
        cmd_research_ranking_eval,
        help="evaluate frozen-cohort ranks against expert truth",
    )
    ranking_evaluator.add_argument("--snapshot", required=True)
    ranking_evaluator.add_argument("--manifest", required=True)
    ranking_evaluator.add_argument("--evidence", required=True)
    ranking_evaluator.add_argument("--truth", required=True)
    ranking_evaluator.add_argument("--out")

    ablation = add_research(
        "ablate",
        cmd_research_ablate,
        help="run read-only predeclared ranking ablations",
    )
    ablation.add_argument("--scenario", action="append", choices=experiments.SCENARIOS)
    ablation.add_argument("--snapshot")
    ablation.add_argument("--manifest")
    ablation.add_argument("--evidence")
    ablation.add_argument("--truth")
    ablation.add_argument("--out")

    stability = add_research(
        "stability",
        cmd_research_stability,
        help="repeat scoring against one frozen assessment snapshot",
    )
    stability.add_argument("--snapshot", required=True)
    stability.add_argument("--repeats", type=int, default=3)
    stability.add_argument("--out")

    add("enrich", cmd_enrich, help="attach CVE intelligence to findings")
    context_parser = add("context", cmd_context, help="infer role, exposure and controls per host")
    context_parser.add_argument(
        "--model", dest="model_artifact", help="use a trained role model with rule fallback"
    )
    rank = add("rank", cmd_rank, help="rank findings with the documented formula")
    rank.add_argument("--top", type=int)
    reporter = add("report", cmd_report, help="write the offline HTML report")
    reporter.add_argument("--out", required=True)
    reporter.add_argument("--snapshot")
    reporter.add_argument("--cohort-manifest")
    reporter.add_argument("--cohort-evidence")
    reporter.add_argument("--scan-artifact")
    reporter.add_argument("--context-artifact")
    reporter.add_argument("--ranking-artifact")
    reporter.add_argument("--ablation-artifact")
    reporter.add_argument("--stability-artifact")
    reporter.add_argument("--unification-artifact")
    reporter.add_argument("--rescan-artifact")
    reporter.add_argument("--model", dest="model_artifact")
    evaluator = add("eval", cmd_eval, help="compare our ranking with expert rankings")
    evaluator.add_argument("--truth")
    evaluator.add_argument("--live", action="store_true")
    two = add("two-machine", cmd_two_machine, help="one CVE, two machines, two answers")
    two.add_argument("--cve")

    unifier = add(
        "unify", cmd_unify_preview, help="preview conservative evidence-preserving grouping"
    )
    unifier.add_argument("--snapshot", required=True)
    unifier.add_argument("--out")

    rescan_parser = add(
        "rescan", cmd_rescan_compare, help="compare hash-verified re-scan observations"
    )
    rescan_parser.add_argument("--before", required=True)
    rescan_parser.add_argument("--after", required=True)
    rescan_parser.add_argument("--out")

    explainer = add("explain", cmd_explain, help="write a plain-English sentence per finding")
    explainer.add_argument("--model", default=explain.DEFAULT_MODEL)
    explainer.add_argument("--ollama-host", default=explain.DEFAULT_HOST)
    explainer.add_argument(
        "--no-model", action="store_true", help="use the deterministic sentence only"
    )

    differ = subparsers.add_parser("diff", help="compare two runs by finding fingerprint")
    differ.add_argument("--json", action="store_true")
    differ.add_argument("--before", required=True)
    differ.add_argument("--after", required=True)
    differ.set_defaults(handler=cmd_diff)

    model_parser = subparsers.add_parser(
        "model", help="train and evaluate the shadow asset-role classifier"
    )
    model_sub = model_parser.add_subparsers(dest="model_command", required=True)

    labels = model_sub.add_parser("labels", help="export unlabeled hosts for human review")
    labels.add_argument("--json", action="store_true")
    labels.add_argument("--run-id", required=True)
    labels.add_argument("--out", required=True)
    labels.set_defaults(handler=cmd_model_labels)

    def add_training_options(command: argparse.ArgumentParser) -> None:
        command.add_argument("--epochs", type=int, default=600)
        command.add_argument("--learning-rate", type=float, default=0.2)
        command.add_argument("--l2", type=float, default=0.001)
        command.add_argument("--min-feature-count", type=int, default=1)
        command.add_argument(
            "--families",
            help=(
                "comma-separated feature families to keep (structure, service, product, "
                "banner, os); omit for all families"
            ),
        )
        command.add_argument("--allow-synthetic", action="store_true")

    trainer = model_sub.add_parser("train", help="fit and save a role-model artifact")
    trainer.add_argument("--json", action="store_true")
    trainer.add_argument("--data", required=True)
    trainer.add_argument("--validation")
    trainer.add_argument("--out", required=True)
    trainer.add_argument(
        "--register",
        action="store_true",
        help="record the dataset and training run in the assessment store",
    )
    trainer.add_argument("--dataset-name", help="dataset name used with --register")
    trainer.add_argument("--dataset-version", default="1")
    trainer.add_argument(
        "--db", default=None, help="assessment store for --register (default: env var or local)"
    )
    add_training_options(trainer)
    trainer.set_defaults(handler=cmd_model_train)

    cross_validator = model_sub.add_parser(
        "cross-validate", help="grouped deterministic cross-validation"
    )
    cross_validator.add_argument("--json", action="store_true")
    cross_validator.add_argument("--data", required=True)
    cross_validator.add_argument("--folds", type=int, default=5)
    add_training_options(cross_validator)
    cross_validator.set_defaults(handler=cmd_model_cross_validate)

    ablator = model_sub.add_parser(
        "ablate", help="cross-validate feature-family subsets to expose shortcut learning"
    )
    ablator.add_argument("--json", action="store_true")
    ablator.add_argument("--data", required=True)
    ablator.add_argument("--folds", type=int, default=5)
    ablator.add_argument(
        "--subsets",
        help=(
            "semicolon-separated family subsets, e.g. "
            "'all;structure;structure,service'; default covers every family alone "
            "plus all-without-banner"
        ),
    )
    add_training_options(ablator)
    ablator.set_defaults(handler=cmd_model_ablate)

    model_evaluator = model_sub.add_parser(
        "evaluate", help="evaluate a frozen artifact on independent labels"
    )
    model_evaluator.add_argument("--json", action="store_true")
    model_evaluator.add_argument("--model", dest="model_artifact", required=True)
    model_evaluator.add_argument("--data", required=True)
    model_evaluator.set_defaults(handler=cmd_model_evaluate)

    predictor = model_sub.add_parser(
        "predict", help="predict run roles in shadow mode without changing ranks"
    )
    predictor.add_argument("--json", action="store_true")
    predictor.add_argument("--run-id", required=True)
    predictor.add_argument("--model", dest="model_artifact", required=True)
    predictor.set_defaults(handler=cmd_model_predict)

    inspector = model_sub.add_parser("inspect", help="inspect artifact metadata and weights")
    inspector.add_argument("--json", action="store_true")
    inspector.add_argument("--model", dest="model_artifact", required=True)
    inspector.add_argument("--top", type=int, default=8)
    inspector.set_defaults(handler=cmd_model_inspect)

    promotion = model_sub.add_parser(
        "validate-promotion", help="validate a fail-closed shadow-model promotion manifest"
    )
    promotion.add_argument("--json", action="store_true")
    promotion.add_argument("--model", dest="model_artifact", required=True)
    promotion.add_argument("--manifest", required=True)
    promotion.add_argument("--as-of", required=True)
    promotion.set_defaults(handler=cmd_model_validate_promotion)

    hybrid = model_sub.add_parser(
        "hybrid-preview", help="preview approved hybrid role recommendations without writes"
    )
    hybrid.add_argument("--json", action="store_true")
    hybrid.add_argument("--run-id", required=True)
    hybrid.add_argument("--model", dest="model_artifact", required=True)
    hybrid.add_argument("--manifest", required=True)
    hybrid.add_argument("--as-of", required=True)
    hybrid.set_defaults(handler=cmd_model_hybrid_preview)

    visualizer = add(
        "visualize", cmd_visualize, help="export the canonical read-only workbench for a run"
    )
    visualizer.add_argument("--model", dest="model_artifact", help=argparse.SUPPRESS)
    visualizer.add_argument("--model-report", help=argparse.SUPPRESS)
    visualizer.add_argument("--out", required=True)

    demo = subparsers.add_parser("demo", help="run the whole pipeline on supplied files")
    demo.add_argument("--json", action="store_true")
    demo.add_argument("--run-id", default="demo")
    demo.add_argument("--target", action="append", required=True, help="IP:nmap.xml[:zap.json]")
    demo.add_argument("--feeds", required=True)
    demo.add_argument("--out", required=True)
    demo.add_argument("--truth")
    demo.set_defaults(handler=cmd_demo)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except VulnAssessError as error:
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        return error.exit_code
