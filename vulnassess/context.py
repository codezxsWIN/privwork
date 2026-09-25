"""Deployment context inferred from the scan evidence itself.

Every returned Feature carries a confidence, a source and a verbatim quote (or 'none observed').
"""

import re
from ipaddress import ip_address
from typing import Any, Iterable, Sequence

from vulnassess.context_facts import interpreted_control as interpreted_control
from vulnassess.errors import ConfigError
from vulnassess.role_model import RoleModel
from vulnassess.schema import ContextProfile, Feature, Finding, Host

CONTROL_KEYS = ("waf", "auth_required", "tls", "rate_limiting")
EVIDENCE_WINDOW = (30, 50)


def _open_ports(host: Host) -> set[int]:
    return {service.port for service in host.services}


def _rule_evidence(host: Host, rule: dict[str, Any]) -> tuple[bool, list[str]]:
    kind = rule.get("match")
    evidence: list[str] = []

    if kind == "port":
        ports = _open_ports(host)
        wanted_all = rule.get("all_of")
        wanted_any = rule.get("any_of")
        if wanted_all:
            if not set(wanted_all) <= ports:
                return False, []
            hits = set(wanted_all)
        elif wanted_any:
            hits = set(wanted_any) & ports
            if not hits:
                return False, []
        else:
            return False, []
        for service in host.services:
            if service.port in hits:
                evidence.append(service.banner or f"{service.port}/{service.protocol}")
        return True, evidence

    pattern = rule.get("regex")
    if not pattern:
        return False, []
    expression = re.compile(pattern, re.IGNORECASE)

    if kind == "os":
        if host.os_guess and expression.search(host.os_guess):
            return True, [host.os_guess]
        return False, []

    attribute = "name" if kind == "service" else "banner"
    if kind not in ("service", "banner"):
        return False, []
    for service in host.services:
        text = getattr(service, attribute) or ""
        if expression.search(text):
            evidence.append(service.banner or text)
    return bool(evidence), evidence


def infer_role(host: Host, rules: dict[str, Any]) -> Feature:
    scores: dict[str, float] = {}
    evidence: dict[str, list[str]] = {}
    for role, role_rules in (rules.get("roles") or {}).items():
        total = 0.0
        quotes: list[str] = []
        for rule in role_rules or []:
            fired, found = _rule_evidence(host, rule)
            if not fired:
                continue
            total += float(rule.get("weight", 0.0))
            quotes.extend(found)
        if total > 0:
            scores[role] = min(total, 1.0)
            evidence[role] = quotes

    if not scores:
        return Feature("unknown", 0.2, "rule", "none observed")

    primary = min(sorted(scores), key=lambda role: (-scores[role], role))
    unique: list[str] = []
    for quote in evidence[primary]:
        if quote and quote not in unique:
            unique.append(quote)
    return Feature(
        primary, round(scores[primary], 2), "rule", "; ".join(unique)[:400] or "none observed"
    )


def infer_exposure(host: Host, scope) -> tuple[Feature, str | None]:
    tags = scope.tags(host.ip)
    name = scope.name(host.ip)
    if tags.get("vantage") == "external":
        quote = f"scope.yaml lab_targets[{name}].tags.vantage=external"
        return Feature("internet_facing", 0.9, "rule", quote), scope.segment(host.ip)
    try:
        globally_routable = ip_address(host.ip).is_global
    except ValueError:
        globally_routable = False
    if globally_routable:
        quote = f"ip {host.ip} is globally routable"
        return Feature("internet_facing", 0.9, "rule", quote), scope.segment(host.ip)
    quote = f"ip {host.ip} is private (RFC1918/loopback/link-local/CGNAT)"
    return Feature("internal", 0.85, "rule", quote), scope.segment(host.ip)


def _texts(host: Host, findings: Sequence[Finding]) -> list[str]:
    texts = [service.banner or "" for service in host.services]
    texts.extend(f"{finding.evidence} {finding.title}" for finding in findings)
    return [text for text in texts if text]


def _window(text: str, match: re.Match[str]) -> str:
    before, after = EVIDENCE_WINDOW
    return text[max(0, match.start() - before) : match.end() + after].strip()


def detect_controls(
    host: Host, findings: Sequence[Finding], signatures: dict[str, Any]
) -> dict[str, Feature]:
    texts = _texts(host, findings)
    controls: dict[str, Feature] = {}

    for key in ("waf", "auth_required", "rate_limiting"):
        found: Feature | None = None
        for signature in signatures.get(key) or []:
            expression = re.compile(signature.get("regex", ""), re.IGNORECASE)
            for text in texts:
                match = expression.search(text)
                if match is None:
                    continue
                value = signature.get("vendor") if key == "waf" else True
                found = Feature(value or True, 0.75, "rule", _window(text, match))
                break
            if found is not None:
                break
        controls[key] = found or Feature(None, 0.0, "rule", "none observed")

    tls_service = next((service for service in host.services if service.tls), None)
    controls["tls"] = (
        Feature(True, 0.9, "rule", tls_service.banner or f"{tls_service.port}/tcp")
        if tls_service is not None
        else Feature(None, 0.0, "rule", "none observed")
    )
    return controls


def build_profile(
    host: Host,
    findings: Iterable[Finding],
    scope,
    rules: dict[str, Any],
    signatures: dict[str, Any],
    model: RoleModel | None = None,
) -> ContextProfile:
    if model is not None:
        raise ConfigError(
            "canonical learned-role activation requires a human-approved context-source ADR; "
            "use 'model predict' or 'model hybrid' for shadow results"
        )
    findings = list(findings)
    exposure, segment = infer_exposure(host, scope)
    manual: dict[str, Feature] = {}
    name = scope.name(host.ip)
    for key, value in sorted(scope.tags(host.ip).items()):
        if key == "vantage":
            continue
        quote = f"scope.yaml lab_targets[{name}].tags.{key}={value}"
        manual[key] = Feature(value, 1.0, "manual", quote)
    role = infer_role(host, rules)
    return ContextProfile(
        host_ip=host.ip,
        role=role,
        exposure=exposure,
        segment=segment,
        controls=detect_controls(host, findings, signatures),
        manual=manual,
    )
