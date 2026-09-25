"""RQ1 evaluation for evidence-derived deployment context.

Truth is host-level and independently reviewed. Synthetic truth can exercise the
arithmetic, but is never eligible to establish H1.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from vulnassess.errors import ConfigError
from vulnassess.role_model import ROLES, RolePrediction
from vulnassess.schema import ContextProfile

TRUTH_SCHEMA_VERSION = 1
EXPOSURES = ("internal", "internet_facing")
CONTROL_KEYS = ("waf", "auth_required", "tls", "rate_limiting")
MISSING = "__missing__"
ABSTAIN = "__abstain__"


@dataclass(frozen=True)
class ContextTruth:
    host_ip: str
    group: str
    role: str
    exposure: str
    controls: dict[str, bool | None] = field(default_factory=dict)
    label_source: str = "human"
    reviewer: str | None = None
    provenance: str = ""

    def __post_init__(self) -> None:
        if not self.host_ip.strip():
            raise ValueError("host_ip is required")
        if not self.group.strip():
            raise ValueError("group must identify an independent host/capture unit")
        if self.role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}, got {self.role!r}")
        if self.exposure not in EXPOSURES:
            raise ValueError(f"exposure must be one of {EXPOSURES}, got {self.exposure!r}")
        unknown = sorted(set(self.controls) - set(CONTROL_KEYS))
        if unknown:
            raise ValueError(f"unknown control truth key {unknown[0]!r}")
        if any(value not in (True, False, None) for value in self.controls.values()):
            raise ValueError("control truth values must be true, false, or null")
        if self.label_source not in ("human", "synthetic"):
            raise ValueError("label_source must be 'human' or 'synthetic'")
        if self.label_source == "human" and not (self.reviewer or "").strip():
            raise ValueError("human context truth requires a reviewer identifier")
        if self.label_source == "human" and not self.provenance.strip():
            raise ValueError("human context truth requires provenance")

    def to_json(self) -> dict[str, Any]:
        return {
            "host_ip": self.host_ip,
            "group": self.group,
            "role": self.role,
            "exposure": self.exposure,
            "controls": dict(self.controls),
            "label_source": self.label_source,
            "reviewer": self.reviewer,
            "provenance": self.provenance,
        }


def load_context_truth(path: str | Path) -> list[ContextTruth]:
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"MISSING: host-context truth file {path}")
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ConfigError(f"{path}: unreadable context truth ({type(error).__name__})") from error
    if not isinstance(payload, dict):
        raise ConfigError(f"{path}: context truth must be a mapping")
    unknown = sorted(set(payload) - {"version", "hosts", "_comment"})
    if unknown:
        raise ConfigError(f"{path}: unknown key {unknown[0]!r}")
    if payload.get("version") != TRUTH_SCHEMA_VERSION:
        raise ConfigError(
            f"{path}: version must be {TRUTH_SCHEMA_VERSION}, got {payload.get('version')!r}"
        )
    rows = payload.get("hosts")
    if not isinstance(rows, list) or not rows:
        raise ConfigError(f"{path}: key 'hosts' must be a non-empty list")

    truth: list[ContextTruth] = []
    seen: set[str] = set()
    allowed = {
        "host_ip",
        "group",
        "role",
        "exposure",
        "controls",
        "label_source",
        "reviewer",
        "provenance",
    }
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ConfigError(f"{path}: hosts[{index}] must be a mapping")
        extra = sorted(set(row) - allowed)
        if extra:
            raise ConfigError(f"{path}: unknown key 'hosts[{index}].{extra[0]}'")
        try:
            item = ContextTruth(
                host_ip=str(row["host_ip"]),
                group=str(row["group"]),
                role=str(row["role"]),
                exposure=str(row["exposure"]),
                controls=dict(row.get("controls") or {}),
                label_source=str(row.get("label_source", "human")),
                reviewer=row.get("reviewer"),
                provenance=str(row.get("provenance") or ""),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ConfigError(f"{path}: invalid hosts[{index}]: {error}") from error
        if item.host_ip in seen:
            raise ConfigError(f"{path}: host {item.host_ip!r} is labelled more than once")
        seen.add(item.host_ip)
        truth.append(item)
    return truth


def _classification(
    actual: Sequence[str],
    predicted: Sequence[str | None],
    classes: Sequence[str],
    abstained: Sequence[bool] | None = None,
) -> dict[str, Any]:
    if len(actual) != len(predicted):
        raise ValueError("actual and predicted lengths differ")
    flags = list(abstained or [False] * len(actual))
    if len(flags) != len(actual):
        raise ValueError("abstention flags and labels differ")
    labels = tuple(sorted(set(classes) | set(actual)))
    columns = (*labels, ABSTAIN, MISSING)
    matrix = {label: {column: 0 for column in columns} for label in labels}
    covered = 0
    correct = 0
    for truth, prediction, did_abstain in zip(actual, predicted, flags, strict=True):
        if prediction is None:
            column = MISSING
        elif did_abstain:
            column = ABSTAIN
        else:
            column = prediction
            covered += 1
            correct += prediction == truth
        if column not in matrix[truth]:
            matrix[truth][column] = 0
        matrix[truth][column] += 1

    per_class: dict[str, dict[str, float | int]] = {}
    f1_values: list[float] = []
    for label in labels:
        support = sum(value == label for value in actual)
        true_positive = sum(
            1
            for truth, prediction, did_abstain in zip(actual, predicted, flags, strict=True)
            if truth == label and prediction == label and not did_abstain
        )
        false_positive = sum(
            1
            for truth, prediction, did_abstain in zip(actual, predicted, flags, strict=True)
            if truth != label and prediction == label and not did_abstain
        )
        false_negative = sum(
            1
            for truth, prediction, did_abstain in zip(actual, predicted, flags, strict=True)
            if truth == label and (prediction != label or did_abstain)
        )
        precision = (
            true_positive / (true_positive + false_positive)
            if true_positive + false_positive
            else 0.0
        )
        recall = (
            true_positive / (true_positive + false_negative)
            if true_positive + false_negative
            else 0.0
        )
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        if support:
            f1_values.append(f1)
        per_class[label] = {
            "support": support,
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
        }

    total = len(actual)
    return {
        "examples": total,
        "accuracy": round(correct / total, 6) if total else None,
        "coverage": round(covered / total, 6) if total else None,
        "abstention_rate": round(sum(flags) / total, 6) if total else None,
        "missing_rate": round(sum(value is None for value in predicted) / total, 6)
        if total
        else None,
        "selective_accuracy": round(correct / covered, 6) if covered else None,
        "macro_f1": round(sum(f1_values) / len(f1_values), 6) if f1_values else None,
        "confusion_matrix": matrix,
        "per_class": per_class,
    }


def _prediction_map(
    predictions: Mapping[str, RolePrediction | Mapping[str, Any]] | None,
) -> dict[str, tuple[str | None, bool, float | None]]:
    result: dict[str, tuple[str | None, bool, float | None]] = {}
    for host_ip, prediction in (predictions or {}).items():
        if isinstance(prediction, RolePrediction):
            result[host_ip] = (
                prediction.label,
                prediction.abstained,
                prediction.confidence,
            )
        else:
            result[host_ip] = (
                prediction.get("label"),
                bool(prediction.get("abstained", False)),
                (None if prediction.get("confidence") is None else float(prediction["confidence"])),
            )
    return result


def evaluate_context(
    profiles: Sequence[ContextProfile],
    truth: Sequence[ContextTruth],
    model_predictions: Mapping[str, RolePrediction | Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compare rule context and optional shadow-model roles against host truth."""
    if not truth:
        raise ConfigError("context evaluation needs at least one labelled host")
    profile_by_ip = {profile.host_ip: profile for profile in profiles}
    if len(profile_by_ip) != len(profiles):
        raise ConfigError("context evaluation received duplicate host profiles")
    model_by_ip = _prediction_map(model_predictions)

    actual_roles = [item.role for item in truth]
    rule_roles: list[str | None] = []
    rule_abstained: list[bool] = []
    model_roles: list[str | None] = []
    model_abstained: list[bool] = []
    actual_exposure = [item.exposure for item in truth]
    inferred_exposure: list[str | None] = []
    missing_profiles: list[str] = []
    disagreements: list[dict[str, Any]] = []

    for item in truth:
        profile = profile_by_ip.get(item.host_ip)
        if profile is None:
            missing_profiles.append(item.host_ip)
            rule_roles.append(None)
            rule_abstained.append(False)
            inferred_exposure.append(None)
        else:
            rule_label = str(profile.role.value)
            rule_roles.append(rule_label)
            rule_abstained.append(rule_label == "unknown")
            inferred_exposure.append(str(profile.exposure.value))

        model_label, did_abstain, confidence = model_by_ip.get(item.host_ip, (None, False, None))
        model_roles.append(model_label)
        model_abstained.append(did_abstain)
        if (
            profile is not None
            and model_label is not None
            and not did_abstain
            and model_label != str(profile.role.value)
        ):
            disagreements.append(
                {
                    "host_ip": item.host_ip,
                    "truth": item.role,
                    "rule": str(profile.role.value),
                    "model": model_label,
                    "model_confidence": confidence,
                    "rule_evidence": profile.role.evidence,
                }
            )

    role_rule = _classification(actual_roles, rule_roles, ROLES, rule_abstained)
    role_model = (
        None
        if model_predictions is None
        else _classification(actual_roles, model_roles, ROLES, model_abstained)
    )
    exposure = _classification(actual_exposure, inferred_exposure, EXPOSURES)

    control_results: dict[str, Any] = {}
    for key in CONTROL_KEYS:
        applicable = [item for item in truth if item.controls.get(key) is not None]
        expected = [str(bool(item.controls[key])).lower() for item in applicable]
        observed: list[str | None] = []
        for item in applicable:
            profile = profile_by_ip.get(item.host_ip)
            feature = None if profile is None else profile.controls.get(key)
            observed.append(
                None
                if feature is None
                or feature.value is None
                or (
                    feature.value is False
                    and feature.source == "rule"
                    and feature.evidence == "none observed"
                )
                else str(bool(feature.value)).lower()
            )
        control_results[key] = _classification(expected, observed, ("false", "true"))

    human_only = all(item.label_source == "human" for item in truth)
    h1 = {
        "eligible": human_only and not missing_profiles,
        "reason": (
            "eligible for H1 interpretation"
            if human_only and not missing_profiles
            else (
                "synthetic labels cannot establish H1"
                if not human_only
                else f"missing profiles for {missing_profiles}"
            )
        ),
        "role_target": 0.85,
        "exposure_target": 0.95,
        "role_pass": (
            role_rule["accuracy"] >= 0.85
            if human_only and not missing_profiles and role_rule["accuracy"] is not None
            else None
        ),
        "exposure_pass": (
            exposure["accuracy"] >= 0.95
            if human_only and not missing_profiles and exposure["accuracy"] is not None
            else None
        ),
    }
    evidence_status = "VERIFIED" if human_only else "NOT RUN"
    return {
        "status": evidence_status,
        "evidence_status": evidence_status,
        "data_kind": "human" if human_only else "synthetic",
        "manual_tags_used": False,
        "truth_hosts": len(truth),
        "truth_groups": len({item.group for item in truth}),
        "missing_profile_hosts": missing_profiles,
        "unlabelled_profile_hosts": sorted(set(profile_by_ip) - {item.host_ip for item in truth}),
        "rule_role": role_rule,
        "model_role": role_model,
        "exposure": exposure,
        "controls": control_results,
        "rule_model_disagreements": disagreements,
        "h1": h1,
    }
