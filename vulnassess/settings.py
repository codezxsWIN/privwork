"""Load and validate config/*.yaml. Files are read locally; nothing is fetched."""

import json
import re
from collections.abc import Set as AbstractSet
from hashlib import sha256
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

import yaml

from vulnassess.errors import ConfigError

CONFIG_FILES = ("scope.yaml", "weights.yaml", "roles.yaml", "controls.yaml")
SCOPE_KEYS = {"allowed_cidrs", "allowed_hosts", "vantage", "lab_targets", "canary"}
TARGET_KEYS = {"name", "ip", "tags"}
TAG_KEYS = {"environment", "criticality", "vantage"}
VANTAGES = ("internal", "external")
ROLE_NAMES = (
    "database",
    "web_frontend",
    "app_server",
    "domain_controller",
    "mail",
    "file_share",
    "iot_embedded",
    "workstation",
    "network_device",
    "unknown",
)


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ConfigError(f"MISSING: configuration file {path}")
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ConfigError(f"{path}: unreadable YAML ({type(error).__name__})") from error
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise ConfigError(f"{path}: expected a mapping at the top level")
    return payload


class Scope:
    """The authorisation fence. A listed address is permitted; nothing else is."""

    def __init__(self, data: dict[str, Any], path: Path) -> None:
        self.path = path
        unknown = set(data) - SCOPE_KEYS
        if unknown:
            raise ConfigError(f"{path}: unknown key {sorted(unknown)[0]!r}")

        cidrs = data.get("allowed_cidrs", [])
        hosts = data.get("allowed_hosts", [])
        targets = data.get("lab_targets", [])
        if not isinstance(cidrs, list):
            raise ConfigError(f"{path}: key 'allowed_cidrs' must be a list")
        if not isinstance(hosts, list):
            raise ConfigError(f"{path}: key 'allowed_hosts' must be a list")
        if not isinstance(targets, list):
            raise ConfigError(f"{path}: key 'lab_targets' must be a list")
        if not cidrs and not hosts:
            raise ConfigError(f"{path}: at least one allowed CIDR or host is required")
        self.networks = [self._network(cidr, "allowed_cidrs") for cidr in cidrs]
        self.hosts = [self._address(host, "allowed_hosts") for host in hosts]
        self.vantage = data.get("vantage", "internal")
        if self.vantage not in VANTAGES:
            raise ConfigError(f"{path}: key 'vantage' must be one of {VANTAGES}")

        self.targets: list[dict[str, Any]] = []
        for target in targets:
            self.targets.append(self._target(target))
        names = [target["name"] for target in self.targets]
        addresses = [target["ip"] for target in self.targets]
        if len(names) != len(set(names)):
            raise ConfigError(f"{path}: lab target names must be unique")
        if len(addresses) != len(set(addresses)):
            raise ConfigError(f"{path}: lab target IPs must be unique")

        self.canary: str | None = None
        canary = data.get("canary")
        if canary is not None:
            if not isinstance(canary, dict) or set(canary) - {"ip"}:
                raise ConfigError(f"{path}: key 'canary' takes only 'ip'")
            self.canary = str(self._address(canary.get("ip"), "canary.ip"))
            if self._inside(self.canary):
                raise ConfigError(
                    f"{path}: key 'canary.ip' {self.canary} is inside the allowed scope; "
                    "the canary must be provably out of scope"
                )

    def _network(self, value: Any, key: str):
        try:
            return ip_network(str(value), strict=False)
        except ValueError as error:
            raise ConfigError(f"{self.path}: key {key!r} value {value!r} is not a CIDR") from error

    def _address(self, value: Any, key: str):
        try:
            return ip_address(str(value))
        except ValueError as error:
            raise ConfigError(
                f"{self.path}: key {key!r} value {value!r} is not an IP address"
            ) from error

    def _target(self, target: Any) -> dict[str, Any]:
        if not isinstance(target, dict):
            raise ConfigError(f"{self.path}: key 'lab_targets' entries must be mappings")
        unknown = set(target) - TARGET_KEYS
        if unknown:
            raise ConfigError(f"{self.path}: unknown key 'lab_targets.{sorted(unknown)[0]}'")
        name = target.get("name")
        if not name:
            raise ConfigError(f"{self.path}: key 'lab_targets.name' is required")
        address = self._address(target.get("ip"), f"lab_targets[{name}].ip")
        tags = target.get("tags") or {}
        if not isinstance(tags, dict):
            raise ConfigError(f"{self.path}: key 'lab_targets[{name}].tags' must be a mapping")
        unknown_tags = set(tags) - TAG_KEYS
        if unknown_tags:
            raise ConfigError(
                f"{self.path}: unknown key 'lab_targets[{name}].tags.{sorted(unknown_tags)[0]}'"
            )
        if "vantage" in tags and tags["vantage"] not in VANTAGES:
            raise ConfigError(
                f"{self.path}: key 'lab_targets[{name}].tags.vantage' must be one of {VANTAGES}"
            )
        if "environment" in tags and tags["environment"] not in ("prod", "test"):
            raise ConfigError(
                f"{self.path}: key 'lab_targets[{name}].tags.environment' must be prod or test"
            )
        criticality = tags.get("criticality")
        if criticality is not None and (type(criticality) is not int or not 1 <= criticality <= 5):
            raise ConfigError(
                f"{self.path}: key 'lab_targets[{name}].tags.criticality' must be an integer 1-5"
            )
        if not self._inside(str(address)):
            raise ConfigError(
                f"{self.path}: key 'lab_targets[{name}].ip' {address} is outside every "
                "allowed_cidrs entry and allowed_hosts entry"
            )
        return {"name": str(name), "ip": str(address), "tags": dict(tags)}

    def _inside(self, ip: str) -> bool:
        try:
            address = ip_address(ip)
        except ValueError:
            return False
        if any(address == host for host in self.hosts):
            return True
        return any(address in network for network in self.networks)

    def contains(self, ip: str) -> bool:
        if self.canary is not None and ip == self.canary:
            return False
        return self._inside(ip)

    def is_canary(self, ip: str) -> bool:
        return self.canary is not None and ip == self.canary

    def segment(self, ip: str) -> str | None:
        try:
            address = ip_address(ip)
        except ValueError:
            return None
        for network in self.networks:
            if address in network:
                return str(network)
        return None

    def tags(self, ip: str) -> dict[str, Any]:
        for target in self.targets:
            if target["ip"] == ip:
                return dict(target["tags"])
        return {}

    def name(self, ip: str) -> str | None:
        for target in self.targets:
            if target["ip"] == ip:
                return target["name"]
        return None

    def allowed(self) -> list[str]:
        return [str(network) for network in self.networks] + [str(host) for host in self.hosts]


class Settings:
    """Every configuration file the pipeline reads, validated once."""

    def __init__(self, config_dir: Path) -> None:
        self.config_dir = Path(config_dir)
        if not self.config_dir.is_dir():
            raise ConfigError(f"MISSING: configuration directory {self.config_dir}")
        self.raw = {name: _read_yaml(self.config_dir / name) for name in CONFIG_FILES}
        self.scope = Scope(self.raw["scope.yaml"], self.config_dir / "scope.yaml")
        self.weights = self.raw["weights.yaml"]
        self.roles = self.raw["roles.yaml"]
        self.controls = self.raw["controls.yaml"]
        self._validate_weights()
        self._validate_roles()
        self._validate_controls()

    @staticmethod
    def _unknown(
        path: Path, data: dict[str, Any], allowed: AbstractSet[str], prefix: str = ""
    ) -> None:
        extra = sorted(set(data) - allowed)
        if extra:
            key = f"{prefix}.{extra[0]}" if prefix else extra[0]
            raise ConfigError(f"{path}: unknown key {key!r}")

    @staticmethod
    def _mapping(path: Path, value: Any, key: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ConfigError(f"{path}: key {key!r} must be a mapping")
        return value

    @staticmethod
    def _number(
        path: Path, value: Any, key: str, minimum: float = 0.0, maximum: float = 1.0
    ) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(f"{path}: key {key!r} must be numeric")
        number = float(value)
        if not minimum <= number <= maximum:
            raise ConfigError(f"{path}: key {key!r} must be in [{minimum}, {maximum}]")
        return number

    @staticmethod
    def _regex(path: Path, value: Any, key: str) -> None:
        if not isinstance(value, str) or not value:
            raise ConfigError(f"{path}: key {key!r} must be a non-empty regex string")
        try:
            re.compile(value, re.IGNORECASE)
        except re.error as error:
            raise ConfigError(f"{path}: key {key!r} has invalid regex: {error}") from error

    def _validate_weights(self) -> None:
        path = self.config_dir / "weights.yaml"
        self._unknown(
            path,
            self.weights,
            {"version", "environmental", "threat", "native_fallback", "bands"},
        )
        for section in ("environmental", "threat", "native_fallback", "bands"):
            if section not in self.weights:
                raise ConfigError(f"{path}: key {section!r} is required")
            self._mapping(path, self.weights[section], section)
        environmental = self.weights["environmental"]
        self._unknown(
            path,
            environmental,
            {
                "internal_when_av_network",
                "waf_present",
                "auth_required_when_pr_none",
                "role_requirements",
                "environment_test",
                "criticality_step_above",
                "min_confidence_to_apply",
            },
            "environmental",
        )
        requirements = self._mapping(
            path, environmental.get("role_requirements"), "environmental.role_requirements"
        )
        missing_roles = sorted(set(ROLE_NAMES) - set(requirements))
        if missing_roles:
            raise ConfigError(
                f"{path}: key 'environmental.role_requirements.{missing_roles[0]}' is required"
            )
        self._unknown(path, requirements, set(ROLE_NAMES), "environmental.role_requirements")
        for role, metrics in requirements.items():
            self._requirements(path, metrics, f"environmental.role_requirements.{role}")
        self._requirements(
            path, environmental.get("environment_test"), "environmental.environment_test"
        )
        self._metric_map(
            path,
            environmental.get("internal_when_av_network"),
            "environmental.internal_when_av_network",
            {"MAV": {"N", "A", "L", "P"}},
        )
        self._metric_map(
            path,
            environmental.get("waf_present"),
            "environmental.waf_present",
            {"MAC": {"L", "H"}},
        )
        self._metric_map(
            path,
            environmental.get("auth_required_when_pr_none"),
            "environmental.auth_required_when_pr_none",
            {"MPR": {"N", "L", "H"}},
        )
        step = environmental.get("criticality_step_above")
        if type(step) is not int or not 1 <= step <= 5:
            raise ConfigError(
                f"{path}: key 'environmental.criticality_step_above' must be an integer 1-5"
            )
        self._number(
            path,
            environmental.get("min_confidence_to_apply"),
            "environmental.min_confidence_to_apply",
        )

        threat = self.weights["threat"]
        expected_threat = {
            "base_multiplier",
            "epss_weight",
            "kev_multiplier",
            "kev_boost",
            "kev_floor_internet_facing",
        }
        self._unknown(path, threat, expected_threat, "threat")
        for key in expected_threat:
            if key not in threat:
                raise ConfigError(f"{path}: key 'threat.{key}' is required")
        base = self._number(path, threat["base_multiplier"], "threat.base_multiplier")
        weight = self._number(path, threat["epss_weight"], "threat.epss_weight")
        kev = self._number(path, threat["kev_multiplier"], "threat.kev_multiplier")
        self._number(path, threat["kev_boost"], "threat.kev_boost", 0, 100)
        self._number(
            path,
            threat["kev_floor_internet_facing"],
            "threat.kev_floor_internet_facing",
            0,
            100,
        )
        if base + weight > 1:
            raise ConfigError(f"{path}: threat.base_multiplier + threat.epss_weight must be <= 1")
        if kev < base:
            raise ConfigError(f"{path}: threat.kev_multiplier must not be below base_multiplier")

        native = self.weights["native_fallback"]
        self._unknown(path, native, {"nessus", "zap", "nikto", "nmap"}, "native_fallback")
        for key in ("nikto", "nmap"):
            self._number(path, native.get(key), f"native_fallback.{key}", 0, 100)
        severities = {"Critical", "High", "Medium", "Low", "Informational"}
        for tool in ("nessus", "zap"):
            severity_weights = self._mapping(path, native.get(tool), f"native_fallback.{tool}")
            allowed_severities = severities - (
                {"Informational"} if tool == "nessus" else {"Critical"}
            )
            self._unknown(path, severity_weights, allowed_severities, f"native_fallback.{tool}")
            for severity in allowed_severities:
                self._number(
                    path,
                    severity_weights.get(severity),
                    f"native_fallback.{tool}.{severity}",
                    0,
                    100,
                )

        bands = self.weights["bands"]
        self._unknown(path, bands, {"Critical", "High", "Medium"}, "bands")
        for band in ("Critical", "High", "Medium"):
            if band not in self.weights["bands"]:
                raise ConfigError(f"{path}: key 'bands.{band}' is required")
            self._number(path, bands[band], f"bands.{band}", 0, 100)
        if not bands["Critical"] > bands["High"] > bands["Medium"]:
            raise ConfigError(f"{path}: bands must be ordered Critical > High > Medium")

    def _requirements(self, path: Path, value: Any, key: str) -> None:
        self._metric_map(
            path,
            value,
            key,
            {"CR": {"H", "M", "L"}, "IR": {"H", "M", "L"}, "AR": {"H", "M", "L"}},
        )

    def _metric_map(
        self,
        path: Path,
        value: Any,
        key: str,
        allowed: dict[str, set[str]],
    ) -> None:
        metrics = self._mapping(path, value, key)
        self._unknown(path, metrics, set(allowed), key)
        if set(metrics) != set(allowed):
            missing = sorted(set(allowed) - set(metrics))
            raise ConfigError(f"{path}: key '{key}.{missing[0]}' is required")
        for metric, choices in allowed.items():
            if metrics[metric] not in choices:
                raise ConfigError(f"{path}: key '{key}.{metric}' must be one of {sorted(choices)}")

    def _validate_roles(self) -> None:
        path = self.config_dir / "roles.yaml"
        self._unknown(path, self.roles, {"ambiguity", "roles"})
        ambiguity = self._mapping(path, self.roles.get("ambiguity"), "ambiguity")
        ambiguity_keys = {"llm_if_top2_within", "llm_if_max_below"}
        self._unknown(path, ambiguity, ambiguity_keys, "ambiguity")
        for key in ambiguity_keys:
            self._number(path, ambiguity.get(key), f"ambiguity.{key}")
        roles = self._mapping(path, self.roles.get("roles"), "roles")
        self._unknown(path, roles, set(ROLE_NAMES) - {"unknown"}, "roles")
        if not roles:
            raise ConfigError(f"{path}: key 'roles' must not be empty")
        for role, rules in roles.items():
            if not isinstance(rules, list) or not rules:
                raise ConfigError(f"{path}: key 'roles.{role}' must be a non-empty list")
            for index, rule in enumerate(rules):
                key = f"roles.{role}[{index}]"
                rule = self._mapping(path, rule, key)
                self._unknown(path, rule, {"match", "any_of", "all_of", "regex", "weight"}, key)
                match = rule.get("match")
                if match not in ("port", "service", "banner", "os"):
                    raise ConfigError(f"{path}: key '{key}.match' is invalid")
                self._number(path, rule.get("weight"), f"{key}.weight")
                if match == "port":
                    choices = rule.get("any_of") if "any_of" in rule else rule.get("all_of")
                    if not isinstance(choices, list) or not choices:
                        raise ConfigError(f"{path}: key '{key}' needs non-empty any_of or all_of")
                    if any(type(port) is not int or not 1 <= port <= 65535 for port in choices):
                        raise ConfigError(f"{path}: key '{key}' contains an invalid port")
                else:
                    self._regex(path, rule.get("regex"), f"{key}.regex")

    def _validate_controls(self) -> None:
        path = self.config_dir / "controls.yaml"
        keys = {"waf", "auth_required", "rate_limiting"}
        self._unknown(path, self.controls, keys)
        for group in keys:
            rules = self.controls.get(group)
            if not isinstance(rules, list) or not rules:
                raise ConfigError(f"{path}: key {group!r} must be a non-empty list")
            for index, rule in enumerate(rules):
                key = f"{group}[{index}]"
                rule = self._mapping(path, rule, key)
                allowed = {"regex", "vendor"} if group == "waf" else {"regex", "note"}
                self._unknown(path, rule, allowed, key)
                self._regex(path, rule.get("regex"), f"{key}.regex")
                detail = "vendor" if group == "waf" else "note"
                if not isinstance(rule.get(detail), str) or not rule[detail].strip():
                    raise ConfigError(f"{path}: key '{key}.{detail}' is required")

    def config_hash(self) -> str:
        payload = json.dumps(self.raw, sort_keys=True, separators=(",", ":"), default=str)
        return sha256(payload.encode("utf-8")).hexdigest()[:16]


def load_settings(config_dir: str | Path = "config") -> Settings:
    return Settings(Path(config_dir))
