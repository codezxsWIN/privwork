"""Trainable shadow model for asset-role inference.

The classifier consumes only fields already present in a Host. It does not write a
ContextProfile and cannot affect ranking. Promote it from shadow mode only after
independent labels, evaluation, and the required policy approval exist.
"""

import json
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Sequence

from vulnassess.errors import ConfigError
from vulnassess.schema import Host

MODEL_SCHEMA_VERSION = 2
MODEL_TASK = "asset_role_shadow"
PREPROCESSING_VERSION = "host-features-v2"
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
MAX_LABEL_BYTES = 32 * 1024 * 1024
MAX_FEATURES = 50_000
ROLES = (
    "app_server",
    "database",
    "domain_controller",
    "file_share",
    "iot_embedded",
    "mail",
    "network_device",
    "unknown",
    "web_frontend",
    "workstation",
)
TOKEN = re.compile(r"[a-z][a-z0-9_.+-]{1,31}")
STRUCTURAL_PREFIXES = (
    "port=",
    "port_proto=",
    "cpe_vendor=",
    "cpe_product=",
    "os=",
    "tls=",
)
# Feature-family ablation support (audit concern 19): banner/product tokens can
# create shortcut learning, so training can restrict features to chosen families.
FEATURE_FAMILIES: dict[str, tuple[str, ...]] = {
    "structure": ("port=", "port_proto=", "tls="),
    "service": ("service=",),
    "product": ("product=", "cpe_vendor=", "cpe_product="),
    "banner": ("banner=",),
    "os": ("os=",),
}


def _family_prefixes(families: Sequence[str] | None) -> tuple[str, ...]:
    if families is None:
        return ()
    unknown = sorted(set(families) - set(FEATURE_FAMILIES))
    if unknown:
        raise ConfigError(
            f"unknown feature family {unknown[0]!r}; choose from {sorted(FEATURE_FAMILIES)}"
        )
    if not families:
        raise ConfigError("feature_families must not be empty; pass None for all families")
    return tuple(prefix for family in sorted(set(families)) for prefix in FEATURE_FAMILIES[family])


def _restrict_rows(
    rows: Sequence[dict[str, float]], prefixes: Sequence[str]
) -> list[dict[str, float]]:
    if not prefixes:
        return list(rows)
    return [
        {name: value for name, value in row.items() if name.startswith(tuple(prefixes))}
        for row in rows
    ]


@dataclass(frozen=True)
class LabelledHost:
    host: Host
    label: str
    group: str
    label_source: str
    reviewer: str | None = None

    def __post_init__(self) -> None:
        if self.label not in ROLES:
            raise ValueError(f"label must be one of {ROLES}, got {self.label!r}")
        if not self.group.strip():
            raise ValueError("group must identify an independent host/capture unit")
        if self.label_source not in ("human", "synthetic"):
            raise ValueError("label_source must be 'human' or 'synthetic'")
        if self.label_source == "human" and not (self.reviewer or "").strip():
            raise ValueError("human labels require a reviewer identifier")

    def to_json(self) -> dict[str, Any]:
        return {
            "host": self.host.to_json(),
            "label": self.label,
            "group": self.group,
            "label_source": self.label_source,
            "reviewer": self.reviewer,
        }


@dataclass(frozen=True)
class RolePrediction:
    label: str
    confidence: float
    margin: float
    abstained: bool
    probabilities: dict[str, float]
    evidence: str
    contributors: tuple[tuple[str, float, str], ...]
    feature_coverage: float
    out_of_vocabulary: tuple[str, ...]
    structural_support: bool
    model_hash: str

    def to_json(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "confidence": self.confidence,
            "margin": self.margin,
            "abstained": self.abstained,
            "probabilities": dict(self.probabilities),
            "evidence": self.evidence,
            "contributors": [
                {"feature": feature, "weight": weight, "evidence": evidence}
                for feature, weight, evidence in self.contributors
            ],
            "feature_coverage": self.feature_coverage,
            "out_of_vocabulary": list(self.out_of_vocabulary),
            "structural_support": self.structural_support,
            "model_hash": self.model_hash,
        }


@dataclass(frozen=True)
class RoleModel:
    classes: tuple[str, ...]
    features: tuple[str, ...]
    coefficients: tuple[tuple[float, ...], ...]
    intercepts: tuple[float, ...]
    temperature: float
    confidence_threshold: float
    margin_threshold: float
    minimum_feature_coverage: float
    training: dict[str, Any]
    schema_version: int = MODEL_SCHEMA_VERSION
    task: str = MODEL_TASK

    def __post_init__(self) -> None:
        if self.schema_version != MODEL_SCHEMA_VERSION or self.task != MODEL_TASK:
            raise ValueError("unsupported role-model artifact")
        if len(self.classes) < 2 or len(set(self.classes)) != len(self.classes):
            raise ValueError("role model needs at least two unique classes")
        if any(label not in ROLES for label in self.classes):
            raise ValueError("role model contains an unknown class")
        if not self.features or len(self.features) > MAX_FEATURES:
            raise ValueError("role model has an invalid feature count")
        if len(self.coefficients) != len(self.classes) or len(self.intercepts) != len(self.classes):
            raise ValueError("role model class dimensions do not match")
        if any(len(row) != len(self.features) for row in self.coefficients):
            raise ValueError("role model feature dimensions do not match")
        if not math.isfinite(self.temperature) or self.temperature <= 0:
            raise ValueError("temperature must be finite and positive")
        for value in (
            self.confidence_threshold,
            self.margin_threshold,
            self.minimum_feature_coverage,
        ):
            if not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError("abstention thresholds must be in [0, 1]")
        numbers = [*self.intercepts, *(value for row in self.coefficients for value in row)]
        if any(not math.isfinite(value) for value in numbers):
            raise ValueError("model coefficients must be finite")

    def core_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "task": self.task,
            "classes": list(self.classes),
            "features": list(self.features),
            "coefficients": [list(row) for row in self.coefficients],
            "intercepts": list(self.intercepts),
            "temperature": self.temperature,
            "confidence_threshold": self.confidence_threshold,
            "margin_threshold": self.margin_threshold,
            "minimum_feature_coverage": self.minimum_feature_coverage,
            "training": self.training,
        }

    @property
    def model_hash(self) -> str:
        return _hash_json(self.core_json())[:16]

    def to_json(self) -> dict[str, Any]:
        return {**self.core_json(), "model_hash": self.model_hash}

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "RoleModel":
        try:
            model = cls(
                schema_version=int(payload["schema_version"]),
                task=str(payload["task"]),
                classes=tuple(str(value) for value in payload["classes"]),
                features=tuple(str(value) for value in payload["features"]),
                coefficients=tuple(
                    tuple(float(value) for value in row) for row in payload["coefficients"]
                ),
                intercepts=tuple(float(value) for value in payload["intercepts"]),
                temperature=float(payload["temperature"]),
                confidence_threshold=float(payload["confidence_threshold"]),
                margin_threshold=float(payload["margin_threshold"]),
                minimum_feature_coverage=float(payload["minimum_feature_coverage"]),
                training=dict(payload["training"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ConfigError(f"invalid role-model artifact: {error}") from error
        claimed = payload.get("model_hash")
        if claimed != model.model_hash:
            raise ConfigError(
                f"role-model hash mismatch: artifact says {claimed!r}, computed {model.model_hash!r}"
            )
        return model

    def probabilities(self, host: Host) -> dict[str, float]:
        values, _ = extract_features(host)
        indexes = {name: index for index, name in enumerate(self.features)}
        vector = {indexes[name]: value for name, value in values.items() if name in indexes}
        logits = []
        for class_index, row in enumerate(self.coefficients):
            score = self.intercepts[class_index]
            score += sum(row[index] * value for index, value in vector.items())
            logits.append(score / self.temperature)
        return dict(zip(self.classes, _softmax(logits), strict=True))

    def predict(self, host: Host) -> RolePrediction:
        values, evidence = extract_features(host)
        vocabulary = set(self.features)
        known = {name: value for name, value in values.items() if name in vocabulary}
        out_of_vocabulary = tuple(sorted(set(values) - vocabulary))
        feature_coverage = len(known) / len(values) if values else 0.0
        probabilities = self.probabilities(host)
        ordered = sorted(probabilities.items(), key=lambda item: (-item[1], item[0]))
        best_label, confidence = ordered[0]
        margin = confidence - ordered[1][1]
        indexes = {name: index for index, name in enumerate(self.features)}
        class_index = self.classes.index(best_label)
        weighted = []
        for feature, value in known.items():
            weight = self.coefficients[class_index][indexes[feature]] * value
            if weight > 0:
                weighted.append((feature, weight, evidence.get(feature, "none observed")))
        weighted.sort(key=lambda item: (-item[1], item[0]))
        contributors = tuple(weighted[:5])
        structural_support = any(
            weight > 0 and feature.startswith(STRUCTURAL_PREFIXES)
            for feature, weight, _ in weighted
        )
        abstained = (
            not known
            or feature_coverage < self.minimum_feature_coverage
            or not structural_support
            or confidence < self.confidence_threshold
            or margin < self.margin_threshold
        )
        label = "unknown" if abstained else best_label
        quotes: list[str] = []
        for _, _, quote in contributors:
            if quote not in quotes:
                quotes.append(quote)
        quote = "; ".join(quotes)[:400] if quotes else "none observed"
        return RolePrediction(
            label=label,
            confidence=round(confidence, 6),
            margin=round(margin, 6),
            abstained=abstained,
            probabilities={key: round(value, 8) for key, value in probabilities.items()},
            evidence=quote,
            contributors=tuple(
                (feature, round(weight, 6), source) for feature, weight, source in contributors
            ),
            feature_coverage=round(feature_coverage, 6),
            out_of_vocabulary=out_of_vocabulary[:50],
            structural_support=structural_support,
            model_hash=self.model_hash,
        )


def _canonical(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _hash_json(payload: Any) -> str:
    return sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _tokens(text: str | None) -> list[str]:
    return TOKEN.findall((text or "").lower())


def _put(values: dict[str, float], evidence: dict[str, str], feature: str, quote: str) -> None:
    values[feature] = 1.0
    evidence.setdefault(feature, quote)


def extract_features(host: Host) -> tuple[dict[str, float], dict[str, str]]:
    """Return binary model features and the verbatim scan quote behind each one."""
    values: dict[str, float] = {}
    evidence: dict[str, str] = {}
    for service in host.services:
        quote = service.banner or f"{service.port}/{service.protocol}"
        _put(values, evidence, f"port={service.port}", quote)
        _put(values, evidence, f"port_proto={service.port}/{service.protocol.lower()}", quote)
        if service.tls:
            _put(values, evidence, "tls=true", quote)
        for token in _tokens(service.name):
            _put(values, evidence, f"service={token}", quote)
        for token in _tokens(service.product):
            _put(values, evidence, f"product={token}", quote)
        for token in _tokens(service.banner):
            _put(values, evidence, f"banner={token}", quote)
        cpe = (service.cpe or "").split(":")
        if service.cpe and service.cpe.startswith("cpe:/") and len(cpe) >= 4:
            _put(values, evidence, f"cpe_vendor={cpe[2].lower()}", quote)
            _put(values, evidence, f"cpe_product={cpe[3].lower()}", quote)
        elif service.cpe and service.cpe.startswith("cpe:2.3:") and len(cpe) >= 5:
            _put(values, evidence, f"cpe_vendor={cpe[3].lower()}", quote)
            _put(values, evidence, f"cpe_product={cpe[4].lower()}", quote)
    if host.os_guess:
        for token in _tokens(host.os_guess):
            _put(values, evidence, f"os={token}", host.os_guess)
    return values, evidence


def dataset_hash(examples: Sequence[LabelledHost]) -> str:
    ordered = sorted((_canonical(example.to_json()) for example in examples))
    return sha256("\n".join(ordered).encode("utf-8")).hexdigest()


def train(
    examples: Sequence[LabelledHost],
    *,
    epochs: int = 600,
    learning_rate: float = 0.2,
    l2: float = 0.001,
    min_feature_count: int = 1,
    confidence_threshold: float = 0.55,
    margin_threshold: float = 0.10,
    minimum_feature_coverage: float = 0.20,
    feature_families: Sequence[str] | None = None,
) -> RoleModel:
    """Fit deterministic, class-balanced multinomial logistic regression."""
    if len(examples) < 4:
        raise ConfigError("role-model training needs at least four labelled hosts")
    classes = tuple(sorted({example.label for example in examples}))
    if len(classes) < 2:
        raise ConfigError("role-model training needs at least two role classes")
    if (
        epochs < 1
        or learning_rate <= 0
        or l2 < 0
        or min_feature_count < 1
        or not 0 <= minimum_feature_coverage <= 1
    ):
        raise ConfigError("invalid role-model training hyperparameters")

    rows = _restrict_rows(
        [extract_features(example.host)[0] for example in examples],
        _family_prefixes(feature_families),
    )
    counts = Counter(name for row in rows for name in row)
    features = tuple(sorted(name for name, count in counts.items() if count >= min_feature_count))
    if not features:
        raise ConfigError("labelled hosts yielded no model features")
    if len(features) > MAX_FEATURES:
        raise ConfigError(f"role-model vocabulary exceeds {MAX_FEATURES} features")

    feature_index = {name: index for index, name in enumerate(features)}
    class_index = {name: index for index, name in enumerate(classes)}
    vectors = [
        {feature_index[name]: value for name, value in row.items() if name in feature_index}
        for row in rows
    ]
    targets = [class_index[example.label] for example in examples]
    class_counts = Counter(targets)
    class_weights = {
        index: len(examples) / (len(classes) * count) for index, count in class_counts.items()
    }
    coefficients = [[0.0 for _ in features] for _ in classes]
    intercepts = [0.0 for _ in classes]

    for _ in range(epochs):
        weight_gradient = [[0.0 for _ in features] for _ in classes]
        intercept_gradient = [0.0 for _ in classes]
        for vector, target in zip(vectors, targets, strict=True):
            logits = [
                intercepts[class_id]
                + sum(coefficients[class_id][index] * value for index, value in vector.items())
                for class_id in range(len(classes))
            ]
            probabilities = _softmax(logits)
            sample_weight = class_weights[target]
            for class_id in range(len(classes)):
                error = probabilities[class_id] - (1.0 if class_id == target else 0.0)
                error *= sample_weight
                intercept_gradient[class_id] += error
                for index, value in vector.items():
                    weight_gradient[class_id][index] += error * value
        scale = 1.0 / len(examples)
        for class_id in range(len(classes)):
            intercepts[class_id] -= learning_rate * intercept_gradient[class_id] * scale
            for index in range(len(features)):
                gradient = weight_gradient[class_id][index] * scale
                gradient += l2 * coefficients[class_id][index]
                coefficients[class_id][index] -= learning_rate * gradient

    return RoleModel(
        classes=classes,
        features=features,
        coefficients=tuple(tuple(value for value in row) for row in coefficients),
        intercepts=tuple(intercepts),
        temperature=1.0,
        confidence_threshold=confidence_threshold,
        margin_threshold=margin_threshold,
        minimum_feature_coverage=minimum_feature_coverage,
        training={
            "algorithm": "multinomial_logistic_regression",
            "preprocessing_version": PREPROCESSING_VERSION,
            "epochs": epochs,
            "learning_rate": learning_rate,
            "l2": l2,
            "class_weight": "balanced",
            "examples": len(examples),
            "groups": len({example.group for example in examples}),
            "label_counts": dict(sorted(Counter(example.label for example in examples).items())),
            "min_feature_count": min_feature_count,
            "feature_families": (
                "all" if feature_families is None else sorted(set(feature_families))
            ),
            "dataset_hash": dataset_hash(examples),
            "label_sources": dict(
                sorted(Counter(example.label_source for example in examples).items())
            ),
            "calibration": "not calibrated: no independent validation set supplied",
        },
    )


def calibrate(model: RoleModel, validation: Sequence[LabelledHost]) -> RoleModel:
    """Select a temperature on independent labels by minimum multiclass log loss."""
    if not validation:
        raise ConfigError("temperature calibration needs an independent validation set")
    unknown = sorted({example.label for example in validation} - set(model.classes))
    if unknown:
        raise ConfigError(f"validation contains class(es) absent from training: {unknown}")
    candidates = [value / 20 for value in range(5, 81)]
    scored = [
        (temperature, _log_loss(model, validation, temperature)) for temperature in candidates
    ]
    temperature, loss = min(scored, key=lambda item: (item[1], item[0]))
    training = {
        **model.training,
        "calibration": {
            "method": "temperature_scaling_grid",
            "temperature": temperature,
            "validation_examples": len(validation),
            "validation_groups": len({example.group for example in validation}),
            "validation_hash": dataset_hash(validation),
            "log_loss": round(loss, 8),
        },
    }
    return replace(model, temperature=temperature, training=training)


def evaluate(model: RoleModel, examples: Sequence[LabelledHost]) -> dict[str, Any]:
    if not examples:
        raise ConfigError("role-model evaluation needs labelled hosts")
    unknown = sorted({example.label for example in examples} - set(model.classes))
    if unknown:
        raise ConfigError(f"evaluation contains class(es) absent from model: {unknown}")

    predictions = [model.predict(example.host) for example in examples]
    actual = [example.label for example in examples]
    predicted = [item.label for item in predictions]
    matrix_labels = (*model.classes, "__abstain__")
    matrix = {label: {other: 0 for other in matrix_labels} for label in model.classes}
    for truth, prediction, result in zip(actual, predicted, predictions, strict=True):
        column = "__abstain__" if result.abstained else prediction
        matrix[truth][column] += 1

    per_class: dict[str, dict[str, float | int]] = {}
    f1_values = []
    for label in model.classes:
        true_positive = sum(
            1
            for truth, result in zip(actual, predictions, strict=True)
            if truth == label and not result.abstained and result.label == label
        )
        false_positive = sum(
            1
            for truth, result in zip(actual, predictions, strict=True)
            if truth != label and not result.abstained and result.label == label
        )
        false_negative = sum(
            1
            for truth, result in zip(actual, predictions, strict=True)
            if truth == label and (result.abstained or result.label != label)
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
        f1_values.append(f1)
        per_class[label] = {
            "support": sum(1 for value in actual if value == label),
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
        }

    covered = [index for index, result in enumerate(predictions) if not result.abstained]
    correct = sum(
        1
        for truth, result in zip(actual, predictions, strict=True)
        if not result.abstained and result.label == truth
    )
    probabilities = [model.probabilities(example.host) for example in examples]
    return {
        "model_hash": model.model_hash,
        "dataset_hash": dataset_hash(examples),
        "examples": len(examples),
        "groups": len({example.group for example in examples}),
        "accuracy": round(correct / len(examples), 6),
        "coverage": round(len(covered) / len(examples), 6),
        "abstention_rate": round(1 - len(covered) / len(examples), 6),
        "selective_accuracy": round(correct / len(covered), 6) if covered else None,
        "macro_f1": round(sum(f1_values) / len(f1_values), 6),
        "log_loss": round(_probability_log_loss(model.classes, probabilities, actual), 8),
        "brier_score": round(_brier(model.classes, probabilities, actual), 8),
        "expected_calibration_error": round(_ece(probabilities, actual), 8),
        "confusion_matrix": matrix,
        "per_class": per_class,
        "predictions": [
            {
                "group": example.group,
                "host_ip": example.host.ip,
                "actual": example.label,
                **prediction.to_json(),
            }
            for example, prediction in zip(examples, predictions, strict=True)
        ],
    }


def cross_validate(
    examples: Sequence[LabelledHost],
    *,
    folds: int = 5,
    epochs: int = 600,
    learning_rate: float = 0.2,
    l2: float = 0.001,
    min_feature_count: int = 1,
    feature_families: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Group-stratified deterministic cross-validation for RQ1."""
    by_group: dict[str, list[LabelledHost]] = defaultdict(list)
    for example in examples:
        by_group[example.group].append(example)
    labels_by_group = {
        group: Counter(item.label for item in items).most_common(1)[0][0]
        for group, items in by_group.items()
    }
    groups_per_class = Counter(labels_by_group.values())
    actual_folds = min(folds, min(groups_per_class.values(), default=0))
    if actual_folds < 2:
        raise ConfigError(
            "cross-validation needs at least two independent groups in every role class"
        )

    fold_groups: list[set[str]] = [set() for _ in range(actual_folds)]
    for label in sorted(groups_per_class):
        groups = sorted(
            (group for group, value in labels_by_group.items() if value == label),
            key=lambda group: sha256(group.encode("utf-8")).hexdigest(),
        )
        for index, group in enumerate(groups):
            fold_groups[index % actual_folds].add(group)

    results = []
    all_groups = set(by_group)
    for index, test_groups in enumerate(fold_groups):
        train_groups = all_groups - test_groups
        training = [item for group in sorted(train_groups) for item in by_group[group]]
        testing = [item for group in sorted(test_groups) for item in by_group[group]]
        model = train(
            training,
            epochs=epochs,
            learning_rate=learning_rate,
            l2=l2,
            min_feature_count=min_feature_count,
            feature_families=feature_families,
        )
        metrics = evaluate(model, testing)
        results.append({"fold": index + 1, "test_groups": sorted(test_groups), **metrics})

    aggregate = {}
    for name in ("accuracy", "coverage", "abstention_rate", "macro_f1", "log_loss", "brier_score"):
        values = [float(result[name]) for result in results]
        aggregate[name] = round(sum(values) / len(values), 8)
    selective = [
        result["selective_accuracy"]
        for result in results
        if result["selective_accuracy"] is not None
    ]
    aggregate["selective_accuracy"] = (
        round(sum(selective) / len(selective), 8) if selective else None
    )
    return {
        "folds": actual_folds,
        "examples": len(examples),
        "groups": len(by_group),
        "dataset_hash": dataset_hash(examples),
        "aggregate": aggregate,
        "results": results,
    }


def ablate_features(
    examples: Sequence[LabelledHost],
    *,
    folds: int = 5,
    subsets: Sequence[Sequence[str] | None] | None = None,
    **options: Any,
) -> dict[str, Any]:
    """Group-aware feature-family ablation.

    Each subset is cross-validated independently on the same group folds so the
    comparison shows which feature families actually carry signal (audit
    concern 19: banner/product shortcut learning). Default subsets: all
    families, each family alone, and everything except banners.
    """
    if subsets is None:
        default_families = sorted(FEATURE_FAMILIES)
        subsets = [
            None,
            *([family] for family in default_families),
            [family for family in default_families if family != "banner"],
        ]
    results = []
    for subset in subsets:
        prefix = "all" if subset is None else "+".join(sorted(set(subset)))
        outcome = cross_validate(examples, folds=folds, feature_families=subset, **options)
        results.append(
            {
                "subset": prefix,
                "folds": outcome["folds"],
                "groups": outcome["groups"],
                "dataset_hash": outcome["dataset_hash"],
                "aggregate": outcome["aggregate"],
            }
        )
    return {
        "examples": len(examples),
        "folds_requested": folds,
        "results": sorted(results, key=lambda item: item["subset"]),
    }


def _softmax(logits: Sequence[float]) -> list[float]:
    largest = max(logits)
    exponents = [math.exp(value - largest) for value in logits]
    total = sum(exponents)
    return [value / total for value in exponents]


def _raw_probabilities(model: RoleModel, host: Host, temperature: float) -> dict[str, float]:
    temporary = replace(model, temperature=temperature)
    return temporary.probabilities(host)


def _log_loss(model: RoleModel, examples: Sequence[LabelledHost], temperature: float) -> float:
    probabilities = [_raw_probabilities(model, item.host, temperature) for item in examples]
    return _probability_log_loss(model.classes, probabilities, [item.label for item in examples])


def _probability_log_loss(
    classes: Sequence[str], probabilities: Sequence[dict[str, float]], actual: Sequence[str]
) -> float:
    del classes
    values = [
        -math.log(max(probability[truth], 1e-15))
        for probability, truth in zip(probabilities, actual, strict=True)
    ]
    return sum(values) / len(values)


def _brier(
    classes: Sequence[str], probabilities: Sequence[dict[str, float]], actual: Sequence[str]
) -> float:
    total = 0.0
    for probability, truth in zip(probabilities, actual, strict=True):
        total += sum(
            (probability[label] - (1.0 if label == truth else 0.0)) ** 2 for label in classes
        )
    return total / len(actual)


def _ece(probabilities: Sequence[dict[str, float]], actual: Sequence[str], bins: int = 10) -> float:
    buckets: list[list[tuple[float, bool]]] = [[] for _ in range(bins)]
    for probability, truth in zip(probabilities, actual, strict=True):
        label, confidence = max(probability.items(), key=lambda item: (item[1], item[0]))
        index = min(int(confidence * bins), bins - 1)
        buckets[index].append((confidence, label == truth))
    total = len(actual)
    error = 0.0
    for bucket in buckets:
        if not bucket:
            continue
        confidence = sum(item[0] for item in bucket) / len(bucket)
        accuracy = sum(item[1] for item in bucket) / len(bucket)
        error += len(bucket) / total * abs(accuracy - confidence)
    return error


def load_examples(path: str | Path) -> list[LabelledHost]:
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"MISSING: labelled-host dataset {path}")
    if path.stat().st_size > MAX_LABEL_BYTES:
        raise ConfigError(f"labelled-host dataset {path} exceeds {MAX_LABEL_BYTES} bytes")
    examples = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
            group = payload["group"]
            if not isinstance(group, str) or not group.strip():
                raise ValueError("group must identify an independently reviewed host/capture unit")
            examples.append(
                LabelledHost(
                    host=Host.from_json(payload["host"]),
                    label=str(payload["label"]),
                    group=group,
                    label_source=str(payload["label_source"]),
                    reviewer=payload.get("reviewer"),
                )
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            raise ConfigError(f"{path}:{line_number}: invalid labelled host: {error}") from error
    if not examples:
        raise ConfigError(f"labelled-host dataset {path} has no examples")
    return examples


def export_label_template(hosts: Iterable[Host], run_id: str, path: str | Path) -> Path:
    """Write unlabeled JSONL for a human reviewer. This is a template, not truth."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for host in sorted(hosts, key=lambda item: item.ip):
        rows.append(
            _canonical(
                {
                    "host": host.to_json(),
                    "label": None,
                    "group": None,
                    "label_source": None,
                    "reviewer": None,
                }
            )
        )
    path.write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")
    return path


def save_model(model: RoleModel, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(_canonical(model.to_json()) + "\n", encoding="utf-8")
    temporary.replace(path)
    return path


def load_model(path: str | Path) -> RoleModel:
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"MISSING: role-model artifact {path}")
    if path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise ConfigError(f"role-model artifact {path} exceeds {MAX_ARTIFACT_BYTES} bytes")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ConfigError(f"invalid role-model artifact {path}: {error}") from error
    if not isinstance(payload, dict):
        raise ConfigError(f"invalid role-model artifact {path}: expected an object")
    return RoleModel.from_json(payload)
