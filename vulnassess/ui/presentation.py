"""The four-stage assessment view. Render stored facts; never rescore a finding."""

import json
from html import escape
from math import cos, radians, sin
from typing import Any

from vulnassess.context_facts import interpreted_control
from vulnassess.ui.drawings import BAND_CLASSES, building, door
from vulnassess.ui.entry import evidence, evidence_items, pipeline_map, run_strip


def _text(value: Any) -> str:
    if value is None:
        return "Not recorded"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value)


def _band(value: str | None) -> str:
    name = value if value in BAND_CLASSES else None
    return f'<span class="band {BAND_CLASSES.get(name or "", "band-unscored")}">{escape(name or "Unscored")}</span>'


VECTOR_LABELS = {
    "AV": "Attack vector",
    "AC": "Attack complexity",
    "PR": "Privileges required",
    "UI": "User interaction",
    "S": "Scope",
    "C": "Confidentiality impact",
    "I": "Integrity impact",
    "A": "Availability impact",
    "CR": "Confidentiality requirement",
    "IR": "Integrity requirement",
    "AR": "Availability requirement",
}
VECTOR_VALUES = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"H": "High", "L": "Low", "N": "None"},
    "I": {"H": "High", "L": "Low", "N": "None"},
    "A": {"H": "High", "L": "Low", "N": "None"},
    "CR": {"H": "High", "M": "Medium", "L": "Low", "X": "Not defined"},
}
# Each weights rule names the metrics it may rewrite and the context feature that triggers it.
CONTEXT_RULES = (
    ("internal_when_av_network", "Internal exposure narrows the attack vector", ("exposure",)),
    ("waf_present", "Observed WAF raises attack complexity", ("controls", "waf")),
    (
        "auth_required_when_pr_none",
        "Observed authentication raises privileges required",
        ("controls", "auth_required"),
    ),
)
REQUIREMENT_METRICS = ("CR", "IR", "AR")


def _vector_metrics(vector: str | None) -> dict[str, str]:
    """Split a stored CVSS vector into its tokens. Nothing is scored here."""
    tokens = str(vector or "").split("/")[1:]
    return dict(token.split(":", 1) for token in tokens if ":" in token)  # type: ignore[misc]


def _metric_name(metric: str) -> str:
    base = metric[1:] if metric.startswith("M") and metric[1:] in VECTOR_LABELS else metric
    label = VECTOR_LABELS.get(base, metric)
    return f"Modified {label.lower()}" if base != metric else label


def _metric_value(metric: str, value: str | None) -> str:
    if value is None:
        return "Not defined"
    base = metric[1:] if metric.startswith("M") else metric
    return VECTOR_VALUES.get("CR" if base in ("IR", "AR") else base, {}).get(value, value)


def _ledger_rows(score: dict[str, Any], environmental: dict[str, Any]) -> list[dict[str, Any]]:
    """Attribute every stored Environmental modification to the rule and evidence behind it."""
    published = _vector_metrics(score.get("base_vector"))
    inputs = score.get("inputs", {}) or {}
    manual = inputs.get("manual", {}) or {}
    rows: list[dict[str, Any]] = []
    for metric, adjusted in (score.get("env_modifications") or {}).items():
        rule = "Recorded modification"
        driver: Any = {}
        for name, description, path in CONTEXT_RULES:
            if metric in (environmental.get(name) or {}):
                rule, driver = description, inputs
                for part in path:
                    driver = driver.get(part, {}) if isinstance(driver, dict) else {}
                break
        else:
            if metric in REQUIREMENT_METRICS:
                environment = manual.get("environment", {}) or {}
                if str(environment.get("value")) == "test":
                    rule, driver = "Test environment overrides the role requirement", environment
                else:
                    rule, driver = (
                        "Asset role sets the security requirement",
                        inputs.get("role", {}),
                    )
        rows.append(
            {
                "metric": metric,
                "published": published.get(metric[1:] if metric.startswith("M") else metric),
                "adjusted": adjusted,
                "rule": rule,
                "driver": driver if isinstance(driver, dict) else {},
            }
        )
    return rows


def _vector_strip(label: str, metrics: dict[str, str], changed: set[str]) -> str:
    empty = '<span class="quiet">No vector stored</span>'
    tokens = "".join(
        f'<span class="vector-token{" vector-token-changed" if key in changed else ""}">'
        f'<span class="vector-key">{escape(key)}</span>'
        f'<span class="vector-value">{escape(value)}</span></span>'
        for key, value in metrics.items()
    )
    return (
        f'<div class="vector-strip"><span class="vector-strip-label">{escape(label)}</span>'
        f'<div class="vector-tokens">{tokens or empty}</div></div>'
    )


def _driver_cell(driver: dict[str, Any]) -> str:
    if not driver:
        return '<span class="quiet">Not recorded</span>'
    return (
        '<div class="ledger-driver">'
        f'<span class="inferred">{escape(_text(driver.get("value")).replace("_", " "))}</span>'
        f'<span class="quiet">{escape(str(driver.get("source", "rule")))} · confidence '
        f"{escape(_text(driver.get('confidence')))}</span>"
        + evidence(driver.get("evidence") or "none observed", "Context / verbatim evidence")
        + "</div>"
    )


def _delta(score: dict[str, Any]) -> str:
    base, env = score.get("base_score"), score.get("env_score")
    if base is None or env is None:
        return "Not comparable"
    return f"{env - base:+.1f}"


def _context_ledger(payload: dict[str, Any], config: dict[str, Any]) -> str:
    """The research thesis, per metric: what context changed and which evidence changed it."""
    environmental = config.get("weights", {}).get("values", {}).get("environmental", {}) or {}
    scored = [
        score
        for score in payload["scores"]
        if score.get("base_vector") and score.get("env_modifications")
    ]
    if not scored:
        return (
            '<div class="state-message" id="context-ledger"><span class="stamp">NO REWRITE</span>'
            "<p>No stored finding in this run carries both a published vector and a recorded "
            "context modification, so there is no rewrite to show.</p></div>"
        )
    top = max(scored, key=lambda score: (score["risk"], score["finding_id"]))
    changed = set(top.get("env_modifications") or {})
    body = "".join(
        "<tr>"
        f'<td class="ledger-metric"><code>{escape(row["metric"])}</code>'
        f'<span class="quiet">{escape(_metric_name(row["metric"]))}</span></td>'
        f'<td class="ledger-was">{escape(_metric_value(row["metric"], row["published"]))}</td>'
        '<td class="ledger-arrow" aria-hidden="true">&rarr;</td>'
        f'<td class="ledger-now">{escape(_metric_value(row["metric"], row["adjusted"]))}</td>'
        f'<td class="ledger-rule">{escape(row["rule"])}</td>'
        f"<td>{_driver_cell(row['driver'])}</td></tr>"
        for row in _ledger_rows(top, environmental)
    )
    rollup = "".join(
        "<tr>"
        f"<td>{evidence(str(score.get('cve_id') or score['finding_id']), 'Stored score / identity', False)}</td>"
        f"<td>{evidence(score['host_ip'], 'Stored score / host', False)}</td>"
        f"<td>{_text(score.get('base_score'))}</td>"
        f"<td>{_text(score.get('env_score'))}</td>"
        f'<td class="ledger-delta">{_delta(score)}</td>'
        f"<td>{len(score.get('env_modifications') or {})}</td>"
        f"<td>{_band(score.get('band'))}</td></tr>"
        for score in scored
    )
    return (
        '<figure class="ledger-figure" id="context-ledger" data-reveal>'
        + _section_header(
            "Context is not free — here is the bill",
            "Every Environmental rewrite, its rule, and the evidence that triggered it",
        )
        + '<figcaption class="ledger-lead">CVSS publishes one severity for everyone. These are the '
        + "metric changes this deployment earned, for "
        + f"<strong>{escape(str(top.get('cve_id') or top['finding_id']))}</strong> on "
        + f"<strong>{escape(top['host_ip'])}</strong>.</figcaption>"
        + '<div class="vector-diff">'
        + _vector_strip("Published", _vector_metrics(top["base_vector"]), set())
        + _vector_strip("Context-adjusted", _vector_metrics(top.get("env_vector")), changed)
        + "</div>"
        + '<table class="ledger-table"><caption class="sr-only">Environmental modifications with '
        + "their rule and evidence</caption><thead><tr><th>Metric</th><th>Published</th><th></th>"
        + "<th>Adjusted</th><th>Rule that applied</th><th>Driving evidence</th></tr></thead>"
        + f"<tbody>{body}</tbody></table>"
        + '<details class="archive"><summary>Every scored finding in this run</summary>'
        + '<table class="record-table ledger-rollup"><thead><tr><th>Identity</th><th>Host</th>'
        + "<th>Published</th><th>Environmental</th><th>Delta</th><th>Rewrites</th><th>Band</th>"
        + f"</tr></thead><tbody>{rollup}</tbody></table></details>"
        + "</figure>"
    )


def _heading(section: str, title: str, sentence: str) -> str:
    return (
        f'<header class="page-heading"><p class="eyebrow">{section}</p>'
        f'<h1>{title}</h1><p class="page-deck">{sentence}</p></header>'
    )


def _section_header(title: str, detail: str = "") -> str:
    return f'<div class="section-head"><h2>{title}</h2><span>{detail}</span></div>'


def _finding_title(finding: dict[str, Any]) -> str:
    return evidence(finding["title"], f"{finding['tool']} / finding title", False)


def _inspection_button(finding: dict[str, Any], content: str, css: str = "inspect-link") -> str:
    return (
        f'<button type="button" class="{css}" data-inspect="{escape(finding["id"])}" '
        f'aria-haspopup="dialog" aria-controls="inspector" aria-label="Inspect {escape(finding["title"])}">'
        f"{content}</button>"
    )


def _finding_marker(finding: dict[str, Any], score: dict[str, Any]) -> str:
    band = score.get("band")
    identity = score.get("cve_id") or next(iter(finding["cve_ids"]), finding["tool_native_id"])
    endpoint = (
        f"{finding['port']}/{finding['protocol']}"
        if finding.get("port") is not None and finding.get("protocol")
        else "host-level"
    )
    return (
        '<span class="finding-marker">'
        '<span class="finding-marker-head">'
        f'<span class="finding-marker-source">{escape(finding["tool"].upper())}</span>'
        f"{_band(band)}</span>"
        f"<strong>{escape(finding['title'])}</strong>"
        f'<span class="finding-marker-meta">{escape(str(identity))} · {escape(endpoint)}</span>'
        "</span>"
    )


def _asset_orbit(payload: dict[str, Any]) -> str:
    profiles = {profile["host_ip"]: profile for profile in payload["context"]}
    selected = payload["scores"][0]["host_ip"] if payload["scores"] else None
    nodes = []
    for index, host in enumerate(payload["hosts"]):
        address = host["ip"]
        profile = profiles.get(address)
        role = profile["role"]["value"] if profile else "unknown"
        count = sum(finding["host_ip"] == address for finding in payload["findings"])
        nodes.append(
            f'<button type="button" class="asset-option" data-asset-select="{escape(address)}" '
            f'aria-pressed="{str(address == selected if selected else index == 0).lower()}" '
            f'aria-label="Select {escape(address)}, {count} stored findings">'
            + f'<span class="asset-option-icon">{building(role)}</span>'
            + f'<span class="asset-option-text">{escape(address)}'
            + f"<small>{escape(str(role).replace('_', ' '))}</small></span>"
            + f'<span class="asset-option-count">{count}</span></button>'
        )
    return (
        '<aside class="asset-browser" aria-label="Recorded assets in this assessment">'
        '<div class="asset-browser-heading"><h2>Assets</h2>'
        f"<span>{len(payload['hosts']):02d}</span></div>"
        '<nav class="asset-options" aria-label="Select an asset">'
        + "".join(nodes)
        + '</nav><div class="asset-browser-footer"><span class="eyebrow">RUN CONFIGURATION</span>'
        + f'<pre class="ascii-field" aria-hidden="true">{escape(payload["run"]["config_hash"])}</pre></div></aside>'
    )


def _priority_focus(payload: dict[str, Any], address: str) -> str:
    findings = {finding["id"]: finding for finding in payload["findings"]}
    score = next((item for item in payload["scores"] if item["host_ip"] == address), None)
    if score is None or score["finding_id"] not in findings:
        return '<p class="state-message">No scored finding recorded for this asset.</p>'
    finding = findings[score["finding_id"]]
    return (
        f'<section class="priority-focus" data-priority-finding="{escape(score["finding_id"])}" '
        'aria-label="Highest stored risk for this asset">'
        '<div class="priority-heading"><div><span class="eyebrow">HIGHEST STORED RISK</span>'
        f"<h2>{escape(finding['title'])}</h2>"
        f'<p class="priority-identity">{escape(str(score.get("cve_id") or finding["tool_native_id"]))}'
        f" / {escape(finding['tool'].upper())}</p></div>"
        f'<div class="priority-number"><strong>{score["risk"]}</strong>'
        f"{_band(score['band'])}<span>Stored risk / 100</span></div></div>"
        '<div class="priority-reason"><h3>Why this matters</h3>'
        f"<p>{escape(score.get('reason') or 'No reason recorded.')}</p></div>"
        '<dl class="priority-inputs"><div><dt>CVSS base</dt>'
        f"<dd>{escape(_text(score.get('base_score')))}</dd></div>"
        "<div><dt>Environmental</dt>"
        f"<dd>{escape(_text(score.get('env_score')))}</dd></div>"
        "<div><dt>EPSS percentile</dt>"
        f"<dd>{escape(_text(score.get('epss_percentile')))}</dd></div>"
        "<div><dt>In CISA KEV</dt>"
        f"<dd>{escape(_text(score.get('kev')))}</dd></div></dl>"
        '<div class="priority-evidence"><h3>Recorded evidence</h3>'
        + evidence(finding["evidence"], f"{finding['tool']} / verbatim finding evidence")
        + '</div><details class="priority-guidance"><summary>Recorded next action</summary>'
        + f"<p>{escape(score.get('fix') or 'No remediation guidance recorded.')}</p></details>"
        + '<div class="priority-actions">'
        + _inspection_button(
            finding, 'Review finding <span aria-hidden="true">&rarr;</span>', "primary-button"
        )
        + f'<button type="button" class="context-action" data-context-asset="{escape(address)}">'
        + 'View context <span aria-hidden="true">&rarr;</span></button></div></section>'
    )


def _evidence_stage(payload: dict[str, Any], config: dict[str, Any]) -> str:
    profiles = {profile["host_ip"]: profile for profile in payload["context"]}
    scores = {score["finding_id"]: score for score in payload["scores"]}
    by_identity = {finding["id"]: finding for finding in payload["findings"]}
    selected = payload["scores"][0]["host_ip"] if payload["scores"] else None
    hosts = []
    for index, host in enumerate(payload["hosts"]):
        profile = profiles.get(host["ip"])
        role = profile["role"]["value"] if profile else "unknown"
        findings = [
            by_identity[score["finding_id"]]
            for score in payload["scores"]
            if score["host_ip"] == host["ip"] and score["finding_id"] in by_identity
        ]
        findings += [
            finding
            for finding in payload["findings"]
            if finding["host_ip"] == host["ip"] and finding["id"] not in scores
        ]
        finding_markers = "".join(
            _inspection_button(
                finding,
                _finding_marker(finding, scores.get(finding["id"], {})),
                "finding-marker-button",
            )
            for finding in findings
        )
        banners = "".join(
            evidence(service["banner"], f"{service['port']}/{service['protocol']} / scanner banner")
            for service in host["services"]
            if service.get("banner")
        )
        hosts.append(
            f'<article class="asset" id="host-{escape(host["ip"])}" '
            f'data-asset-panel="{escape(host["ip"])}"'
            + (" hidden" if (host["ip"] != selected if selected else index != 0) else "")
            + ">"
            + '<div class="asset-cap"><span class="eyebrow">ASSET / '
            + f'{index + 1:02d}</span><span class="asset-service-count">{len(host["services"])} services</span></div>'
            + evidence(host["ip"], "Scanner / host address", False)
            + f'<h3 class="inferred">{escape(role.replace("_", " "))}</h3>'
            + f'<p class="asset-exposure">{escape(str(profile["exposure"]["value"]).replace("_", " ") if profile else "No context recorded")}</p>'
            + _priority_focus(payload, host["ip"])
            + f'<div class="section-head asset-findings-heading"><h2>All findings</h2><span>{len(findings)} recorded</span></div>'
            + f'<div class="asset-findings">{finding_markers or "No findings recorded"}</div>'
            + f'<details class="asset-evidence"><summary>Scanner evidence</summary>{banners or "No banner recorded"}</details>'
            + "</article>"
        )
    scope = config.get("scope", {})
    scope_values = scope.get("values", {})
    targets = scope_values.get("lab_targets", [])
    allowlist = "".join(
        evidence(target["ip"], "Scope / explicit lab target", False) for target in targets
    )
    canary = scope_values.get("canary", {}).get("ip")
    fence = (
        '<div class="scope-fence"><div><span class="eyebrow">PERMISSION BOUNDARY</span>'
        "<h2>The fence is part of the evidence.</h2></div>"
        f'<div class="scope-targets">{allowlist or "Configuration not attached"}</div>'
        '<div class="canary-record"><span class="stamp">OUT OF SCOPE</span>'
        + (
            evidence(canary, "Scope / canary address", False)
            if canary
            else "<p>Canary not recorded</p>"
        )
        + '<p class="quiet">Refusal history is not stored.</p></div></div>'
    )
    feeds = "".join(
        '<article class="feed"><div class="feed-heading">'
        f'<h3>{escape(feed["feed"].upper())}</h3><span class="stamp">SNAPSHOT</span></div>'
        + evidence(feed["file_date"] or "Not recorded", "Feed / snapshot date", False)
        + '<p class="quiet">Age in days: not stored</p>'
        + evidence(str(feed["rows"]), "Feed / stored rows", False)
        + f"<details><summary>Snapshot provenance</summary>{evidence(feed['sha256'], 'Feed / SHA-256')}"
        + evidence(feed["path"], "Feed / source path")
        + "</details></article>"
        for feed in payload["feeds_meta"]
    )
    return (
        '<section id="stage-evidence" class="stage-panel" data-panel="evidence" aria-labelledby="evidence-title">'
        + _heading(
            "01 / EVIDENCE / " + escape(payload["run"]["run_id"]),
            '<span id="evidence-title">Vulnerability review<span class="heading-period">.</span></span>',
            f"{len(payload['hosts'])} assets / {len(payload['findings'])} findings / {len(payload['scores'])} scored",
        )
        + '<div class="evidence-explorer">'
        + _asset_orbit(payload)
        + '<div class="asset-stack"><div class="deck-toolbar"><span class="eyebrow">SELECTED ASSET</span>'
        + '<div class="deck-controls"><button type="button" class="icon-button" data-deck-step="-1" aria-label="Previous asset" title="Previous asset">&larr;</button>'
        + f'<output id="deck-position" aria-live="polite">{1 if hosts else 0} / {len(hosts)}</output>'
        + '<button type="button" class="icon-button" data-deck-step="1" aria-label="Next asset" title="Next asset">&rarr;</button></div></div>'
        + f'<div class="asset-grid asset-deck">{"".join(hosts) or "No hosts recorded."}</div></div></div>'
        + '<details class="archive scope-archive"><summary>Authorized scope and canary</summary>'
        + fence
        + "</details>"
        + _section_header("Intelligence snapshots", "Current store metadata; not frozen per run")
        + f'<div class="feed-grid">{feeds or "No feed metadata recorded"}</div>'
        + '<details class="archive"><summary>Recorded pipeline details</summary>'
        + pipeline_map(payload)
        + "</details>"
        + "</section>"
    )


def _feature(feature: dict[str, Any], label: str, threshold: float | None = None) -> str:
    confidence = feature["confidence"]
    state = '<span class="stamp">MANUAL</span>' if feature["source"] == "manual" else ""
    if threshold is not None and confidence < threshold:
        state += '<span class="stamp">BELOW SCORING THRESHOLD</span>'
    ring = (
        f'<svg class="confidence-ring" viewBox="0 0 40 40" aria-hidden="true">'
        '<circle cx="20" cy="20" r="15" class="ring-track"/>'
        f'<circle cx="20" cy="20" r="15" class="ring-value" pathLength="1" '
        f'stroke-dasharray="{confidence} 1"/></svg>'
    )
    return (
        '<div class="feature-row"><div class="feature-name">'
        f'<span class="eyebrow">{escape(label)}</span>{state}</div>'
        f'<div class="feature-value"><span class="inferred">{escape(("Unknown" if feature["value"] is None else _text(feature["value"])).replace("_", " "))}</span>'
        f'<span class="confidence" aria-label="Confidence {confidence}">{ring}{confidence}</span></div>'
        + '<details class="feature-evidence"><summary>Source evidence</summary>'
        + evidence(feature["evidence"], f"{feature['source']} / {label} evidence")
        + "</details></div>"
    )


def _context_stage(payload: dict[str, Any], config: dict[str, Any]) -> str:
    threshold = (
        config.get("weights", {})
        .get("values", {})
        .get("environmental", {})
        .get("min_confidence_to_apply")
    )
    profiles = []
    selectors = []
    for profile in payload["context"]:
        selectors.append(
            f'<button type="button" class="context-tab" data-asset-select="{escape(profile["host_ip"])}" '
            'aria-pressed="false">'
            + building(profile["role"]["value"])
            + f"<span>{escape(profile['host_ip'])}<small>{escape(str(profile['role']['value']).replace('_', ' '))}</small></span></button>"
        )
        features = _feature(profile["role"], "Role", threshold) + _feature(
            profile["exposure"], "Exposure", threshold
        )
        features += "".join(
            _feature(interpreted_control(feature), name.replace("_", " "), threshold)
            for name, feature in profile["controls"].items()
        )
        features += "".join(
            _feature(feature, name.replace("_", " ")) for name, feature in profile["manual"].items()
        )
        score_rows = "".join(
            '<button type="button" class="context-score" '
            f'data-inspect="{escape(score["finding_id"])}" aria-haspopup="dialog" aria-controls="inspector">'
            f"<span>{escape(str(score.get('cve_id') or 'Native finding'))}</span>"
            f'<span class="context-score-chain">{_text(score.get("base_score"))} <i aria-hidden="true">&rarr;</i> '
            f'{_text(score.get("env_score"))} <i aria-hidden="true">&rarr;</i> <strong>{score["risk"]}</strong></span>'
            f"{_band(score['band'])}</button>"
            for score in payload["scores"]
            if score["host_ip"] == profile["host_ip"]
        )
        profiles.append(
            f'<article class="context-column" id="context-{escape(profile["host_ip"])}" '
            f'data-context-panel="{escape(profile["host_ip"])}">'
            + '<div class="context-profile"><div class="context-profile-heading">'
            + evidence(profile["host_ip"], "Stored context / host", False)
            + f'<div class="context-mark">{building(profile["role"]["value"])}</div>'
            + f'</div><div class="context-features">{features}</div></div>'
            + '<aside class="context-consequence"><span class="eyebrow">CONTEXT / PRIORITY</span>'
            + '<h2>What changed?</h2><p class="quiet">Stored base &rarr; environmental &rarr; risk</p>'
            + (score_rows or '<p class="state-message">No score recorded for this asset.</p>')
            + '<a class="context-action" href="#stage-risk">Compare the risk inputs <span aria-hidden="true">&rarr;</span></a></aside>'
            + "</article>"
        )
    return (
        '<section id="stage-context" class="stage-panel" data-panel="context" hidden>'
        + _heading(
            "02 / CONTEXT",
            "The context behind the priority.",
            "Recorded role, exposure, controls and their supporting evidence.",
        )
        + f'<div class="context-selector" aria-label="Choose an asset">{"".join(selectors)}</div>'
        + '<p id="context-empty" class="state-message" hidden>No context profile recorded for this asset.</p>'
        + f'<div class="context-grid">{"".join(profiles) or "No context profiles stored"}</div>'
        + '<details class="model-workspace"><summary>Local analyst <span class="quiet">Advisory / explicit request only</span></summary>'
        + '<div class="section-head"><div><span class="eyebrow">LOCAL AI SECURITY ANALYST</span><h2 id="model-title">Analyze the complete target.</h2></div>'
        + '<span class="model-badge">Ollama / grounded evidence</span></div>'
        + '<p class="model-copy">The local model reads every stored service, finding, context inference, CVSS record, EPSS signal and KEV flag for one target. Its actions must cite records from this assessment.</p>'
        + '<div class="model-controls"><label for="model-host">Asset</label><select id="model-host">'
        + _analyst_choices(payload)
        + f'</select><button id="run-model" class="primary-button" type="button"{"" if _analyzable_hosts(payload) else " disabled"}>Review local analysis</button></div>'
        + '<div id="model-output" class="model-output" aria-live="polite"><span class="model-placeholder">Select an asset to ask the local analyst for correlations and an evidence-backed remediation sequence.</span></div>'
        + "</details>"
        + '<p class="stage-footnote">AI analysis is advisory. Canonical risk remains the transparent stored calculation; unknown citations or malformed model output are rejected.</p></section>'
    )


def _analyzable_hosts(payload: dict[str, Any]) -> set[str]:
    """Hosts whose stored finding set can form an analyst case."""
    return {item["host_ip"] for item in payload["findings"]}


def _analyst_choices(payload: dict[str, Any]) -> str:
    """Analyst asset options; hosts without stored findings are disabled, not refused after the click."""
    analyzable = _analyzable_hosts(payload)
    options = []
    for profile in payload["context"]:
        host_ip = escape(profile["host_ip"])
        role = escape(_text(profile["role"]["value"]).replace("_", " "))
        if profile["host_ip"] in analyzable:
            options.append(f'<option value="{host_ip}">{host_ip} · {role}</option>')
        else:
            options.append(
                f'<option value="{host_ip}" disabled>{host_ip} · {role} — no stored findings</option>'
            )
    return "".join(options)


def _pair(payload: dict[str, Any]) -> list[dict[str, Any]]:
    scores = payload["scores"]
    for score in scores:
        if score.get("cve_id"):
            candidates = [item for item in scores if item.get("cve_id") == score["cve_id"]]
            if len({item["host_ip"] for item in candidates}) > 1:
                lower = min(candidates, key=lambda item: (item["risk"], item["finding_id"]))
                other = next(item for item in candidates if item["host_ip"] != lower["host_ip"])
                return [lower, other]
    return []


def _comparison(payload: dict[str, Any]) -> str:
    pair = _pair(payload)
    if not pair:
        return '<div class="state-message"><span class="stamp">NO COMPARISON</span><p>No scored CVE is shared across hosts in this run.</p></div>'
    rows = []
    rowspec = [
        ("Base score", [score["base_score"] for score in pair]),
        ("Role", [score["inputs"].get("role", {}).get("value") for score in pair]),
        ("Exposure", [score["inputs"].get("exposure", {}).get("value") for score in pair]),
        ("Environmental", [score["env_score"] for score in pair]),
        ("EPSS percentile", [score["epss_percentile"] for score in pair]),
        ("KEV", [score["kev"] for score in pair]),
        ("Risk", [score["risk"] for score in pair]),
        ("Band", [score["band"] for score in pair]),
    ]
    for label, values in rowspec:
        state = ' class="differs"' if values[0] != values[1] else ""
        cells = "".join(f"<td>{escape(_text(value).replace('_', ' '))}</td>" for value in values)
        rows.append(f'<tr{state}><th scope="row">{label}</th>{cells}</tr>')
    illustrations = "".join(
        '<div class="compare-asset">'
        + building(score["inputs"].get("role", {}).get("value", "unknown"))
        + evidence(score["host_ip"], "Stored score / host", False)
        + f'<div class="compare-risk {BAND_CLASSES.get(score["band"], "")}"><strong>{score["risk"]}</strong>{_band(score["band"])}</div>'
        + "</div>"
        for score in pair
    )
    return (
        '<div class="comparison" id="comparison"><div class="shared-weakness"><span class="eyebrow">ONE SHARED WEAKNESS</span>'
        + evidence(pair[0]["cve_id"], "Stored score / shared CVE", False)
        + '<span class="comparison-connector" aria-hidden="true"></span></div>'
        + f'<div class="compare-assets">{illustrations}</div>'
        + '<table id="compare-table" class="compare-table"><caption class="sr-only">Same vulnerability on two hosts</caption>'
        + f"<thead><tr><th>Stored input or result</th><th>{escape(pair[0]['host_ip'])}</th><th>{escape(pair[1]['host_ip'])}</th></tr></thead>"
        + f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


def _flatten(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    if not isinstance(value, dict):
        return [(prefix, value)]
    return [
        item
        for key, child in value.items()
        for item in _flatten(child, f"{prefix}.{key}".strip("."))
    ]


def _threat_strip(payload: dict[str, Any]) -> str:
    """Run hero: stored counts (animated up by app.js) plus a band-composition meter."""
    scores = payload["scores"]
    kev = sum(1 for score in scores if score.get("kev"))
    exposed = sum(
        1
        for score in scores
        if score.get("inputs", {}).get("exposure", {}).get("value") == "internet_facing"
    )
    percentiles = [
        score["epss_percentile"] for score in scores if score.get("epss_percentile") is not None
    ]
    cells = [
        ("Findings scored", len(scores)),
        ("Distinct CVEs", len({score["cve_id"] for score in scores if score.get("cve_id")})),
        ("KEV-listed", kev),
        ("Internet-facing", exposed),
    ]
    if percentiles:
        cells.append(("Top EPSS percentile", round(max(percentiles) * 100)))
    rendered = "".join(
        f'<div class="threat-cell"><span class="threat-value" data-count="{value}">{value}</span>'
        f'<span class="threat-label">{escape(label)}</span></div>'
        for label, value in cells
    )
    bands = ["Critical", "High", "Medium", "Low"]
    counts = {band: sum(1 for score in scores if score.get("band") == band) for band in bands}
    meter = "".join(
        f'<span class="meter-seg meter-{band.lower()}" title="{band}: {counts[band]}"></span>'
        for band in bands
        for _ in range(counts[band])
    )
    legend = "".join(
        f'<span class="meter-key meter-{band.lower()}">{band} {counts[band]}</span>'
        for band in bands
        if counts[band]
    )
    return (
        '<div class="threat-strip" data-reveal data-reveal-group="threat">'
        + f'<div class="threat-cells">{rendered}</div>'
        + '<div class="threat-meter-wrap">'
        + '<div class="threat-meter" role="img" aria-label="Findings by band: '
        + ", ".join(f"{band} {counts[band]}" for band in bands if counts[band])
        + f'">{meter}</div><div class="meter-legend">{legend}</div></div>'
        + '<p class="threat-note">Counts over stored findings in this run.</p></div>'
    )


def _quadrant(payload: dict[str, Any]) -> str:
    """Stored CVSS base vs EPSS percentile, one point per scored finding.

    Positions come straight from the store; nothing is rescored here. Findings
    without an EPSS row sit in an explicit lane below the axis instead of
    pretending to a percentile.
    """
    scored = [score for score in payload["scores"] if score.get("base_score") is not None]
    if not scored:
        return (
            '<div class="state-message" data-reveal><span class="stamp">NO QUADRANT</span>'
            "<p>No scored findings in this run, so there is nothing to place on the map.</p></div>"
        )
    width, height = 720, 430
    left, right, top = 56, 28, 34
    lane_top = height - 52
    plot_w, plot_h = width - left - right, lane_top - top

    def x_of(base: float) -> float:
        return left + (min(max(base, 0.0), 10.0) / 10.0) * plot_w

    def y_of(percentile: float) -> float:
        return top + (1.0 - min(max(percentile, 0.0), 1.0)) * plot_h

    marks: list[str] = []
    for index, score in enumerate(scored):
        base = float(score["base_score"])
        percentile = score.get("epss_percentile")
        jitter = (index % 3 - 1) * 5
        if percentile is None:
            cx = x_of(base) + jitter
            cy = lane_top + 18 + (index % 2) * 10
            lane_note = "no EPSS row"
        else:
            cx = x_of(base) + jitter
            cy = y_of(float(percentile))
            lane_note = f"EPSS {round(float(percentile) * 100)}%"
        hollow = score.get("inputs", {}).get("exposure", {}).get("value") != "internet_facing"
        band_class = BAND_CLASSES.get(score.get("band") or "", "band-unscored")
        ring = (
            f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="14" class="quad-ring" aria-hidden="true"/>'
            if score.get("kev")
            else ""
        )
        cross = (
            f'<line x1="{left}" y1="{cy:.1f}" x2="{cx:.1f}" y2="{cy:.1f}" class="quad-cross"/>'
            f'<line x1="{cx:.1f}" y1="{cy:.1f}" x2="{cx:.1f}" y2="{lane_top}" class="quad-cross"/>'
        )
        marks.append(
            f'<g class="quad-point quad-enter {band_class}{" quad-hollow" if hollow else ""}" '
            f'data-inspect="{escape(score["finding_id"])}" tabindex="0" role="button" '
            f'aria-label="Inspect {escape(score.get("cve_id") or score.get("finding_id", ""))} '
            f"on {escape(score['host_ip'])}: stored risk {score['risk']}, "
            f'{escape(score.get("band") or "unscored")}, {lane_note}">'
            f"<title>{escape(str(score.get('cve_id') or ''))} on {escape(score['host_ip'])} "
            f"— base {base}, {lane_note}, stored risk {score['risk']}</title>"
            f'{cross}{ring}<circle cx="{cx:.1f}" cy="{cy:.1f}" r="8.5"/></g>'
        )

    guides = (
        f'<line x1="{x_of(9.0):.1f}" y1="{top}" x2="{x_of(9.0):.1f}" y2="{lane_top}" class="quad-guide"/>'
        f'<line x1="{left}" y1="{y_of(0.5):.1f}" x2="{width - right}" y2="{y_of(0.5):.1f}" class="quad-guide"/>'
    )
    zones = (
        f'<rect x="{x_of(7.0):.1f}" y="{top}" width="{width - right - x_of(7.0):.1f}" '
        f'height="{y_of(0.5) - top:.1f}" class="quad-zone quad-zone-danger"/>'
        f'<rect x="{left}" y="{top}" width="{x_of(7.0) - left:.1f}" '
        f'height="{y_of(0.5) - top:.1f}" class="quad-zone quad-zone-watch"/>'
    )
    labels = (
        f'<text x="{left + plot_w - 10}" y="{top + 18}" class="quad-label quad-label-strong" text-anchor="end">high severity · high exploitation</text>'
        f'<text x="{left + 10}" y="{top + 18}" class="quad-label">exploitation leads severity</text>'
        f'<text x="{left + plot_w - 10}" y="{lane_top - 10}" class="quad-label" text-anchor="end">high severity · thin exploitation</text>'
        f'<text x="{left + 10}" y="{lane_top - 10}" class="quad-label">monitor</text>'
    )
    axis = "".join(
        f'<text x="{x_of(tick):.1f}" y="{lane_top + 18}" '
        f'class="quad-tick" text-anchor="middle">{tick}</text>'
        for tick in (0, 2.5, 5, 7.5, 10)
    ) + "".join(
        f'<text x="{left - 10}" y="{y_of(tick) + 4:.1f}" class="quad-tick" text-anchor="end">{int(tick * 100)}</text>'
        for tick in (0.0, 0.5, 1.0)
    )
    defs = (
        "<defs>"
        '<linearGradient id="quad-danger-fill" x1="0" y1="0" x2="1" y2="1">'
        '<stop offset="0" stop-color="var(--critical)" stop-opacity="0.02"/>'
        '<stop offset="1" stop-color="var(--critical)" stop-opacity="0.16"/></linearGradient>'
        '<linearGradient id="quad-watch-fill" x1="1" y1="0" x2="0" y2="1">'
        '<stop offset="0" stop-color="var(--medium)" stop-opacity="0.02"/>'
        '<stop offset="1" stop-color="var(--medium)" stop-opacity="0.09"/></linearGradient>'
        "</defs>"
    )
    return (
        '<figure class="quadrant-figure" data-reveal>'
        + _section_header(
            "Severity meets exploitation", "Stored CVSS base against stored EPSS percentile"
        )
        + f'<svg id="quadrant-map" viewBox="0 0 {width} {height}" role="img" '
        + 'aria-label="Scatter map of findings by CVSS base score and EPSS percentile">'
        + defs
        + zones
        + f'<line x1="{left}" y1="{top}" x2="{left}" y2="{lane_top}" class="quad-axis"/>'
        + f'<line x1="{left}" y1="{lane_top}" x2="{width - right}" y2="{lane_top}" class="quad-axis"/>'
        + f'<line x1="{left}" y1="{lane_top + 36}" x2="{width - right}" y2="{lane_top + 36}" '
        + 'class="quad-axis quad-axis-dashed"/>'
        + guides
        + axis
        + labels
        + "".join(marks)
        + f'<text x="{width - right}" y="{height - 8}" class="quad-tick" text-anchor="end">'
        + "no EPSS row — ranked on environmental score alone</text>"
        + "</svg>"
        + '<figcaption class="quad-caption">Select a point to inspect its stored inputs. '
        + "Ringed points are in CISA KEV; hollow points are not internet-facing. "
        + "The queued priorities always come from the stored risk, never from this map.</figcaption>"
        + "</figure>"
    )


def _dial(top: dict[str, Any]) -> str:
    """Gauge for the stored risk of the top finding. Arc geometry is static; the
    fill animates from 0 via a CSS variable app.js drives (reduced-motion safe)."""
    cx, cy, radius = 130.0, 112.0, 92.0
    risk = min(max(float(top["risk"]), 0.0), 100.0)
    start = (cx - radius * 0.866, cy + radius * 0.5)
    end = (cx + radius * 0.866, cy + radius * 0.5)
    arc = f"M {start[0]:.1f} {start[1]:.1f} A {radius} {radius} 0 1 1 {end[0]:.1f} {end[1]:.1f}"
    band_class = BAND_CLASSES.get(top.get("band") or "", "band-unscored")
    ticks = "".join(
        f'<line x1="{cx + (radius - 6) * x:.1f}" y1="{cy - (radius - 6) * y:.1f}" '
        f'x2="{cx + radius * x:.1f}" y2="{cy - radius * y:.1f}" class="dial-tick" '
        f'opacity="{1.0 if value <= risk else 0.35}"/>'
        for value, x, y in (
            (v, _cos_deg(210 - 2.4 * v), _sin_deg(210 - 2.4 * v)) for v in (0, 25, 50, 75, 100)
        )
    )
    return (
        '<div class="dial" data-reveal>'
        + f'<svg viewBox="0 0 260 168" role="img" data-dial="{risk:.0f}" '
        + f'aria-label="Stored risk {top["risk"]} of 100, band {top.get("band")}">'
        + f'<path d="{arc}" class="dial-track" pathLength="100"/>'
        + f'<path d="{arc}" class="dial-value {band_class}" pathLength="100" '
        + 'stroke-dasharray="0 100"/>'
        + ticks
        + f'<text x="{cx}" y="{cy - 6}" class="dial-number" text-anchor="middle">'
        + f'<tspan data-count="{risk:.0f}">{risk:.0f}</tspan></text>'
        + f'<text x="{cx}" y="{cy + 14}" class="dial-band" text-anchor="middle">{escape(str(top.get("band") or ""))}</text>'
        + f'<text x="{start[0]:.1f}" y="{start[1] + 14:.1f}" class="quad-tick" text-anchor="middle">0</text>'
        + f'<text x="{end[0]:.1f}" y="{end[1] + 14:.1f}" class="quad-tick" text-anchor="middle">100</text>'
        + "</svg></div>"
    )


def _cos_deg(angle: float) -> float:
    return cos(radians(angle))


def _sin_deg(angle: float) -> float:
    return sin(radians(angle))


def _beams(top: dict[str, Any], weights: dict[str, Any]) -> str:
    """The four stations of the formula, joined by animated flow paths.

    Every value is stored: base, environmental, the threat factor terms, the
    final risk. The moving dashes are presentation only.
    """
    threat = weights.get("threat", {})
    epss = top.get("epss_percentile")
    multiplier = (
        None
        if epss is None
        else float(threat.get("base_multiplier", 0.5))
        + float(threat.get("epss_weight", 0.5)) * float(epss)
    )
    if top.get("kev"):
        multiplier = max(multiplier or 0.0, float(threat.get("kev_multiplier", 1.0)))
    threat_text = "unscored" if multiplier is None else f"×{multiplier:.2f}"
    threat_sub = (
        "no EPSS row"
        if epss is None
        else f"{threat.get('base_multiplier', 0.5)} + {threat.get('epss_weight', 0.5)} × EPSS"
        + (" · KEV" if top.get("kev") else "")
    )
    stations = [
        ("Base", f"{top.get('base_score')}", "beam-base", "scanner + NVD vector"),
        ("Context", f"{top.get('env_score')}", "beam-env", "environmental auto-fill"),
        ("Threat", threat_text, "beam-threat", threat_sub),
        ("Risk", f"{top['risk']}", "beam-final", str(top.get("band") or "")),
    ]
    cy, radius = 54, 17
    xs = [72, 254, 436, 618]
    nodes = []
    for (name, value, css, sub), x in zip(stations, xs, strict=True):
        nodes.append(
            '<g class="beam-node beam-enter">'
            f'<circle cx="{x}" cy="{cy}" r="{radius}" class="{css}"/>'
            f'<text x="{x}" y="{cy + 4}" class="beam-node-value" text-anchor="middle">{escape(value)}</text>'
            f'<text x="{x}" y="{cy - radius - 10}" class="beam-node-name" text-anchor="middle">{escape(name)}</text>'
            f'<text x="{x}" y="{cy + radius + 16}" class="beam-node-sub" text-anchor="middle">{escape(sub)}</text>'
            "</g>"
        )
    links = []
    for index in range(len(xs) - 1):
        x1, x2 = xs[index] + radius + 6, xs[index + 1] - radius - 6
        y = cy
        links.append(
            f'<path d="M {x1} {y} C {x1 + 40} {y}, {x2 - 40} {y}, {x2} {y}" class="beam-base"/>'
            f'<path d="M {x1} {y} C {x1 + 40} {y}, {x2 - 40} {y}, {x2} {y}" class="beam-dash" '
            f'data-sequence="{index}"/>'
        )
    return (
        '<div class="beams" data-reveal>'
        + '<svg viewBox="0 0 690 110" role="img" aria-label="Risk formation: base severity, '
        + 'context, threat factor, final risk">'
        + "".join(links)
        + "".join(nodes)
        + "</svg></div>"
    )


def _formation(payload: dict[str, Any], weights: dict[str, Any]) -> str:
    """Dial + beams: the engine view of how the top stored risk formed."""
    scored = [score for score in payload["scores"] if score.get("base_vector")]
    if not scored:
        return ""
    top = max(scored, key=lambda score: (score["risk"], score["finding_id"]))
    return (
        '<figure class="formation-figure" data-reveal>'
        + _section_header(
            "The formation engine",
            "How one finding became the top priority - stored values, animated presentation",
        )
        + '<div class="formation-grid">'
        + _dial(top)
        + _beams(top, weights)
        + "</div>"
        + '<figcaption class="quad-caption">The dial and beams replay the recorded arithmetic; '
        + "they cannot invent a new score. Change the assumptions yourself in the sandbox below "
        + "to see what the model would have said.</figcaption>"
        + "</figure>"
    )


def _waterfall(payload: dict[str, Any], weights: dict[str, Any]) -> str:
    """How the stored risk formed, segment by segment, from stored numbers only."""
    scored = [score for score in payload["scores"] if score.get("base_vector")]
    if not scored:
        return ""
    top = max(scored, key=lambda score: (score["risk"], score["finding_id"]))
    threat = weights.get("values", {}).get("threat", {})
    env = top.get("env_score")
    multiplier = (
        None
        if top.get("epss_percentile") is None
        else float(threat.get("base_multiplier", 0.5))
        + float(threat.get("epss_weight", 0.5)) * float(top["epss_percentile"])
    )
    if top.get("kev"):
        multiplier = max(multiplier or 0.0, float(threat.get("kev_multiplier", 1.0)))
    segments: list[tuple[str, float, str]] = []
    if env is not None:
        base_contribution = float(env) * 10.0
        segments.append(
            ("Context-adjusted severity (environmental × 10)", base_contribution, "wf-fill-base")
        )
        if multiplier is not None and multiplier != 1.0:
            segments.append(
                (
                    f"× exploitation multiplier {multiplier:.2f}",
                    base_contribution * (multiplier - 1.0),
                    "wf-fill-threat",
                )
            )
        if top.get("kev"):
            segments.append(
                (
                    f"KEV boost +{threat.get('kev_boost', 10)}",
                    float(threat.get("kev_boost", 10)),
                    "wf-fill-kev",
                )
            )
        uncapped = sum(value for _, value, _ in segments)
        if uncapped > 100:
            segments.append(("Capped at 100", -(uncapped - 100.0), "wf-fill-cap"))
    else:
        segments.append(("Native fallback (no CVE match)", float(top["risk"]), "wf-fill-base"))
    widest = max((abs(value) for _, value, _ in segments), default=1.0) or 1.0
    bars = "".join(
        f'<div class="wf-row"><span class="wf-label">{escape(label)}</span>'
        '<span class="wf-track"><svg viewBox="0 0 100 10" preserveAspectRatio="none" '
        f'aria-hidden="true"><rect class="wf-fill {css}" x="0" y="0" '
        f'width="{max(abs(value), 0.6) / widest * 100:.1f}" height="10"/></svg>'
        f'<i class="wf-number">{value:+.1f}</i></span></div>'
        for label, value, css in segments
    )
    band_class = BAND_CLASSES.get(top.get("band") or "", "band-unscored")
    total_row = (
        f'<div class="wf-row wf-total"><span class="wf-label">Stored risk</span>'
        '<span class="wf-track"><svg viewBox="0 0 100 10" preserveAspectRatio="none" '
        f'aria-hidden="true"><rect class="wf-fill wf-fill-result {band_class}" x="0" y="0" '
        f'width="{min(max(float(top["risk"]), 0.0), 100.0):.1f}" height="10"/></svg>'
        f'<i class="wf-number wf-result">{top["risk"]} · {escape(str(top.get("band") or ""))}</i>'
        "</span></div>"
    )
    return (
        '<figure class="waterfall-figure" data-reveal>'
        + _section_header(
            "How the top risk formed", "Stored arithmetic for the highest-risk finding"
        )
        + f'<div class="waterfall" id="risk-waterfall" data-inspect="{escape(top["finding_id"])}">'
        + bars
        + total_row
        + "</div>"
        + f'<figcaption class="wf-caption">Stored risk <strong>{top["risk"]}</strong> '
        + f"({_band(top.get('band'))}) for {escape(str(top.get('cve_id') or top.get('finding_id')))} "
        + f"on {escape(top['host_ip'])}. threat = {threat.get('base_multiplier', 0.5)} + "
        + f"{threat.get('epss_weight', 0.5)} × EPSS percentile; the formula and its hash live in "
        + "config/weights.yaml. Select the bar to inspect the stored inputs.</figcaption>"
        + "</figure>"
    )


def _risk_stage(payload: dict[str, Any], config: dict[str, Any]) -> str:
    weights = config.get("weights", {})
    rows = "".join(
        f"<tr><th>{evidence(key, 'Configuration / key', False)}</th><td>{evidence(_text(value), 'Configuration / value', False)}</td></tr>"
        for key, value in _flatten(weights.get("values", {}))
    )
    return (
        '<section id="stage-risk" class="stage-panel" data-panel="risk" hidden>'
        + _heading(
            "03 / RISK",
            "Same weakness.<br><em>Different urgency.</em>",
            "Context changes the priority. The original severity stays visible.",
        )
        + _threat_strip(payload)
        + _comparison(payload)
        + _context_ledger(payload, config)
        + _quadrant(payload)
        + _formation(payload, weights.get("values", {}))
        + _waterfall(payload, weights.get("values", {}))
        + _sandbox(payload, config)
        + '<details class="archive" id="weights-view"><summary>The weights, in the open</summary>'
        + evidence(weights.get("sha256", "Not attached"), "Current weights file / SHA-256")
        + '<p class="quiet">Current configuration, not a reconstruction of historical weights.</p>'
        + f'<table class="record-table"><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>{rows}</tbody></table></details></section>'
    )


def _sandbox(payload: dict[str, Any], config: dict[str, Any]) -> str:
    candidates = [score for score in payload["scores"] if score.get("base_vector")]
    weights = config.get("weights", {}).get("values", {})
    if not candidates or not weights:
        return '<p class="state-message">Sandbox unavailable: a stored CVSS vector and current weights are required.</p>'
    options = "".join(
        f'<option value="{score["finding_id"]}">{escape(score["host_ip"])} / {escape(score["cve_id"] or "CVSS")}</option>'
        for score in candidates
    )
    roles = "".join(
        f'<option value="{escape(role)}">{escape(role.replace("_", " "))}</option>'
        for role in weights["environmental"]["role_requirements"]
    )
    return (
        '<section class="sandbox" id="sandbox" aria-labelledby="sandbox-heading">'
        '<div class="sandbox-banner"><span class="stamp">SANDBOX</span><strong>Sandbox. Nothing stored changes.</strong></div>'
        '<div class="section-head"><h2 id="sandbox-heading">What would change?</h2><button id="sandbox-reset" class="text-button" type="button">Reset assumptions</button></div>'
        '<p class="quiet">Calculated in this browser using current configuration. The assessment above stays unchanged.</p>'
        '<form id="sandbox-form"><div class="sandbox-controls">'
        f'<label class="sandbox-finding">Finding<select name="finding">{options}</select></label>'
        f'<label>Role<select name="role">{roles}</select></label>'
        '<label>Exposure<select name="exposure"><option value="internal">Internal</option><option value="internet_facing">Internet-facing</option></select></label>'
        '<label>Environment<select name="environment"><option value="prod">Production</option><option value="test">Test</option></select></label>'
        '<label class="check-control"><input name="waf" type="checkbox">WAF observed</label>'
        '<label class="check-control"><input name="kev" type="checkbox">Listed in KEV</label>'
        '<label class="check-control"><input name="epss-missing" type="checkbox">EPSS absent</label>'
        '<label class="epss-control">EPSS percentile <output id="sandbox-epss">Not calculated</output><input name="epss" type="range" min="0" max="1" step="0.0001" aria-label="Sandbox EPSS percentile"></label>'
        '</div></form><div class="sandbox-results" aria-live="polite">'
        '<div><span>Environmental</span><output id="sandbox-environmental">Not calculated</output></div>'
        '<div><span>Threat multiplier</span><output id="sandbox-threat">Not calculated</output></div>'
        '<div><span>Hypothetical risk</span><output id="sandbox-risk">Not calculated</output></div>'
        '<div><span>Band</span><output id="sandbox-band">Not calculated</output></div>'
        '</div><p id="sandbox-error" role="alert" hidden></p>'
        '<details><summary>Calculated vector</summary><pre id="sandbox-vector" class="sandbox-vector"></pre></details>'
        '<details><summary>CVSS arithmetic self-check</summary><button id="selfcheck" class="text-button" type="button">Run local arithmetic check</button><output id="selfcheck-result" aria-live="polite">Not run</output></details>'
        "</section>"
    )


def _facets(payload: dict[str, Any]) -> str:
    profiles = {profile["host_ip"]: profile for profile in payload["context"]}
    specs = (
        ("band", "Band", sorted({score["band"] for score in payload["scores"]})),
        ("host", "Host", sorted({finding["host_ip"] for finding in payload["findings"]})),
        ("scanner", "Scanner", sorted({finding["tool"] for finding in payload["findings"]})),
        (
            "exposure",
            "Exposure",
            sorted({profile["exposure"]["value"] for profile in profiles.values()}),
        ),
        ("kev", "KEV", ["yes", "no"]),
        ("cve", "CVE", ["yes", "no"]),
        ("unscored", "Threat unscored", ["yes", "no"]),
    )
    return (
        '<div class="facets">'
        + "".join(
            f'<label>{label}<select data-facet="{key}" aria-label="Filter {label}"><option value="">All</option>'
            + "".join(
                f'<option value="{escape(value)}">{escape(value.replace("_", " "))}</option>'
                for value in values
            )
            + "</select></label>"
            for key, label, values in specs
        )
        + '<button type="button" class="text-button" id="clear-filters">Clear</button></div>'
    )


def _priorities_stage(payload: dict[str, Any]) -> str:
    finding_map = {finding["id"]: finding for finding in payload["findings"]}
    profiles = {profile["host_ip"]: profile for profile in payload["context"]}
    rows = []
    ordered = [
        (finding_map[score["finding_id"]], score)
        for score in payload["scores"]
        if score["finding_id"] in finding_map
    ]
    scored = {score["finding_id"] for score in payload["scores"]}
    ordered += [(finding, {}) for finding in payload["findings"] if finding["id"] not in scored]
    for finding, score in ordered:
        exposure = profiles.get(finding["host_ip"], {}).get("exposure", {}).get("value", "unknown")
        data = {
            "band": score.get("band", "Unscored"),
            "host": finding["host_ip"],
            "scanner": finding["tool"],
            "exposure": exposure,
            "kev": "yes" if score.get("kev") else "no",
            "cve": "yes" if finding["cve_ids"] or score.get("cve_id") else "no",
            "unscored": "yes" if score.get("threat_multiplier") is None else "no",
        }
        attrs = " ".join(f'data-{key}="{escape(value)}"' for key, value in data.items())
        risk = score.get("risk")
        risk_text = "Unscored" if risk is None else str(risk)
        meter = (
            ""
            if risk is None
            else f'<meter class="risk-meter" min="0" max="100" value="{risk}" aria-label="Stored risk {risk}"></meter>'
        )
        rows.append(
            f'<tr class="queue-row" {attrs}><td class="risk-cell {BAND_CLASSES.get(score.get("band"), "")}">'
            f"<span>{risk_text}</span>{meter}</td><td>{_band(score.get('band'))}</td>"
            f"<td>{_inspection_button(finding, escape(finding['title']), 'finding-link')}"
            + evidence(
                ", ".join(finding["cve_ids"]) or score.get("cve_id") or finding["tool_native_id"],
                "Scanner / vulnerability identifier",
                False,
            )
            + f'</td><td>{evidence(finding["host_ip"], "Scanner / host", False)}<span class="quiet">{escape(exposure.replace("_", " "))}</span></td>'
            + f"<td>{evidence(finding['tool'], 'Provenance / scanner', False)}</td></tr>"
        )
    return (
        '<section id="stage-priorities" class="stage-panel" data-panel="priorities" hidden>'
        + _heading(
            "04 / PRIORITIES",
            "What deserves attention first?",
            "The stored order. Every finding still connected to its evidence.",
        )
        + _facets(payload)
        + '<div class="table-scroll"><table id="ranked-list" class="queue-table"><thead><tr><th>Risk</th><th>Band</th><th>Finding</th><th>Host</th><th>Source</th></tr></thead>'
        + f"<tbody>{''.join(rows)}</tbody></table></div>"
        + '<p id="no-results" class="state-message" hidden>No findings match these filters.</p>'
        + '<section class="evaluation"><span class="stamp">NOT EVALUATED HERE</span><h2>A ranking is a hypothesis.</h2>'
        "<p>No persisted expert-evaluation result is attached to this run. Kendall's W, tau, NDCG and critical queue are unavailable.</p>"
        '<p class="quiet">This viewer does not compute or substitute evaluation metrics.</p></section></section>'
    )


def _anatomy(score: dict[str, Any]) -> str:
    nodes = (
        ("Base", score.get("base_score")),
        ("Environmental", score.get("env_score")),
        ("Risk", score.get("risk")),
    )
    flow = "".join(
        f'<div class="score-node"><span>{name}</span><strong>{escape(_text(value))}</strong></div>'
        for name, value in nodes
    )
    modifications = "".join(
        f"<tr><th>{escape(metric)}</th><td>{evidence(value, 'Stored Environmental modification', False)}</td></tr>"
        for metric, value in score.get("env_modifications", {}).items()
    )
    return (
        f'<div class="score-chain" aria-label="Stored score chain">{flow}</div>'
        + evidence(score.get("base_vector") or "No vector stored", "Stored score / base vector")
        + evidence(
            score.get("env_vector") or "Native severity path", "Stored score / Environmental vector"
        )
        + f'<table class="record-table"><tbody>{modifications}</tbody></table>'
        + '<p class="quiet">Rule names and historical weight values were not persisted per modification.</p>'
        + evidence(_text(score.get("epss_percentile")), "Stored score / EPSS percentile", False)
        + evidence(
            "Threat unscored"
            if score.get("threat_multiplier") is None
            else str(score["threat_multiplier"]),
            "Stored score / threat multiplier",
            False,
        )
        + evidence(
            score.get("native_fallback") or "Environmental scoring path",
            "Stored score / fallback",
            False,
        )
    )


def _chain(
    finding: dict[str, Any],
    score: dict[str, Any],
    enrichments: list[dict[str, Any]],
    context_used: dict[str, Any],
) -> str:
    """Raw record to rank, one stored value per hop."""
    provenance = finding.get("provenance", {}) or {}
    match = enrichments[0] if enrichments else {}
    role = context_used.get("role", {}) or {}
    exposure = context_used.get("exposure", {}) or {}
    steps = (
        (
            "Captured",
            f"{finding['tool']} record {_text(provenance.get('record_index'))}",
            _text(provenance.get("raw_path")),
        ),
        (
            "Normalised",
            finding["id"],
            f"{finding['host_ip']}:{_text(finding.get('port'))}/{_text(finding.get('protocol'))}",
        ),
        (
            "Matched",
            _text(match.get("cve_id")) if match else "No CVE match recorded",
            f"{_text(match.get('match_method'))} · confidence {_text(match.get('match_confidence'))}"
            if match
            else "Ranked through the native severity path",
        ),
        (
            "Contextualised",
            f"{_text(role.get('value')).replace('_', ' ')} · "
            f"{_text(exposure.get('value')).replace('_', ' ')}",
            f"role {_text(role.get('confidence'))} ({_text(role.get('source'))}) · "
            f"exposure {_text(exposure.get('confidence'))} ({_text(exposure.get('source'))})",
        ),
        (
            "Rescored",
            f"{_text(score.get('base_score'))} → {_text(score.get('env_score'))}",
            f"{len(score.get('env_modifications') or {})} Environmental metrics rewritten",
        ),
        (
            "Ranked",
            f"{_text(score.get('risk'))} · {_text(score.get('band'))}",
            f"threat multiplier {_text(score.get('threat_multiplier'))} · "
            f"weights {_text(score.get('weights_hash'))}",
        ),
    )
    items = "".join(
        f'<li class="chain-step"><span class="chain-index">{index:02d}</span>'
        f'<span class="chain-label">{escape(label)}</span>'
        f'<span class="chain-value">{escape(str(value))}</span>'
        f'<span class="chain-detail">{escape(str(detail))}</span></li>'
        for index, (label, value, detail) in enumerate(steps, start=1)
    )
    return f'<ol class="chain">{items}</ol>'


def _inspector(payload: dict[str, Any]) -> str:
    scores = {score["finding_id"]: score for score in payload["scores"]}
    profiles = {profile["host_ip"]: profile for profile in payload["context"]}
    panels = []
    for finding in payload["findings"]:
        score = scores.get(finding["id"], {})
        enrichments = [
            item for item in payload["enrichments"] if item["finding_id"] == finding["id"]
        ]
        references = sorted(
            {reference for item in enrichments for reference in item.get("patch_references", [])}
        )
        fix = (
            evidence(score["fix"], "Stored score / recorded recommendation")
            + "".join(
                evidence(reference, "Enrichment / recorded advisory reference")
                for reference in references
            )
            if score.get("fix") and references
            else "<p>No vendor fix recorded in the loaded feeds.</p>"
        )
        related = [
            item
            for item in payload["findings"]
            if item["id"] != finding["id"]
            and item["host_ip"] != finding["host_ip"]
            and set(item["cve_ids"]) & set(finding["cve_ids"])
        ]
        provenance = "".join(
            evidence(_text(value), f"Provenance / {key}", False)
            for key, value in finding["provenance"].items()
        )
        provenance += evidence(finding["first_seen"], "Finding / first seen", False)
        provenance += evidence(finding["last_seen"], "Finding / last seen", False)
        context_used = score.get("inputs", {}) or profiles.get(finding["host_ip"], {})
        context_markup = "".join(
            _feature(context_used[key], key.capitalize())
            for key in ("role", "exposure")
            if key in context_used
        )
        context_markup += (
            "<details><summary>Controls and manual tags</summary>"
            + "".join(
                _feature(value, key.replace("_", " "))
                for collection in (context_used.get("controls", {}), context_used.get("manual", {}))
                for key, value in collection.items()
            )
            + "</details>"
        )
        stored_detail = {
            "finding": finding,
            "score": score,
            "enrichments": enrichments,
            "context_used": context_used,
        }
        panels.append(
            f'<article class="inspection" id="inspection-{escape(finding["id"])}" data-inspection="{escape(finding["id"])}" hidden>'
            + f'<span class="eyebrow">FINDING / {escape(finding["tool"].upper())}</span>'
            + f"<h2>{escape(finding['title'])}</h2>{_band(score.get('band'))}"
            + f'<p class="inspector-reason">{escape(score.get("reason", "No reason recorded"))}</p>'
            + "<h3>Chain of custody</h3>"
            + _chain(finding, score, enrichments, context_used)
            + "<h3>How this score was recorded</h3>"
            + _anatomy(score)
            + "<h3>Evidence</h3>"
            + evidence(finding["evidence"], f"{finding['tool']} / verbatim finding evidence")
            + "<details><summary>Context used</summary>"
            + (context_markup or '<p class="quiet">Context inputs not recorded.</p>')
            + "</details>"
            + "<h3>Recommended fix</h3>"
            + fix
            + '<h3>Back to the source</h3><div class="provenance">'
            + provenance
            + "</div>"
            + "<h3>Same CVE, elsewhere</h3>"
            + (
                "".join(_inspection_button(item, escape(item["host_ip"])) for item in related)
                or '<p class="quiet">No other host shares this recorded CVE.</p>'
            )
            + "<details><summary>Complete stored record</summary>"
            + evidence(json.dumps(stored_detail, indent=2), "Database / complete finding record")
            + "</details>"
            + "</article>"
        )
    return (
        '<dialog id="inspector" class="inspector" aria-label="Finding inspector">'
        '<div class="inspector-bar"><span class="eyebrow">EVIDENCE INSPECTOR</span>'
        '<button id="close-inspector" class="icon-button" type="button" aria-label="Close inspector" title="Close inspector">'
        '<svg aria-hidden="true" viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>'
        + "".join(panels)
        + "</dialog>"
    )


def _project_story(payload: dict[str, Any] | None, runs: list[dict[str, Any]]) -> str:
    header = (
        '<section id="project-story" class="project-section project-story" '
        'aria-labelledby="project-story-title"><div class="project-section-heading">'
        '<span class="eyebrow">01 / WHY CONTEXT MATTERS</span>'
        '<h2 id="project-story-title">A warning needs its surroundings.</h2>'
        "<p>The same weakness can appear on very different systems. "
        "The question is where to look first.</p></div>"
    )
    if payload is None:
        options = "".join(
            f'<option value="{escape(run["run_id"])}">{escape(run["run_id"])}</option>'
            for run in runs
        )
        selection = (
            '<label class="story-run-choice">Explore a recorded assessment'
            '<select id="select-project-run"><option value="">Choose an assessment</option>'
            + options
            + "</select></label>"
            if runs
            else '<p class="story-absence">No assessment has been recorded here yet.</p>'
        )
        return header + selection + "</section>"

    candidates = [score for score in payload["scores"] if score.get("cve_id")]
    pair: list[dict[str, Any]] = []
    for first in candidates:
        match = next(
            (
                second
                for second in candidates
                if first["host_ip"] != second["host_ip"]
                and first.get("base_vector")
                and first.get("base_score") is not None
                and all(
                    first.get(key) == second.get(key)
                    for key in ("cve_id", "base_vector", "base_score", "epss_percentile", "kev")
                )
            ),
            None,
        )
        if match is not None:
            pair = sorted([first, match], key=lambda item: (item["risk"], item["finding_id"]))
            break
    if not pair:
        return (
            header + '<div class="story-absence"><h3>No like-for-like example in this run.</h3>'
            "<p>This assessment does not contain the same recorded vulnerability and threat "
            "inputs on two different systems. Its findings are still available in the workflow.</p>"
            "</div></section>"
        )
    synthetic = any("synthetic" in item["path"].lower() for item in payload["feeds_meta"]) or any(
        "synthetic" in item["provenance"]["raw_path"].lower() for item in payload["findings"]
    )
    kind = "Synthetic example" if synthetic else "Recorded example"
    note = (
        "Illustrative data, not findings about real systems."
        if synthetic
        else "Stored records, not proof that context caused the difference."
    )
    roles = {
        "database": "A database system",
        "workstation": "A workstation",
        "web_frontend": "A web-facing system",
        "app_server": "An application server",
        "domain_controller": "An identity server",
        "mail": "A mail server",
        "file_share": "A file-sharing system",
        "network_device": "A network device",
        "iot_embedded": "An embedded device",
        "unknown": "An unclassified system",
    }
    findings = {finding["id"]: finding for finding in payload["findings"]}
    systems: list[str] = []
    for index, score in enumerate(pair):
        inputs = score.get("inputs") or {}
        role = inputs.get("role") or {}
        exposure = inputs.get("exposure") or {}
        environment = (inputs.get("manual") or {}).get("environment") or {}
        role_value = role.get("value")
        exposure_value = exposure.get("value")
        environment_value = environment.get("value")
        surroundings = (
            {
                "internal": "Internal network",
                "internet_facing": "Internet-facing",
            }.get(exposure_value, "Reachability not recorded")
            if isinstance(exposure_value, str)
            else "Reachability not recorded"
        )
        usage = (
            {"test": "Test use", "prod": "Production use"}.get(environment_value)
            if isinstance(environment_value, str)
            else None
        ) or "Use not recorded"
        role_name = (
            roles.get(role_value) if isinstance(role_value, str) else None
        ) or "A recorded system"
        outcome = (
            "Same recorded priority"
            if pair[0]["risk"] == pair[1]["risk"]
            else "Later in this recorded queue"
            if index == 0
            else "Earlier in this recorded queue"
        )
        finding = findings.get(score["finding_id"])
        quote = finding["evidence"] if finding else "No finding record attached."
        systems.append(
            f'<article class="story-system" data-story-finding="{escape(score["finding_id"])}">'
            f'<span class="story-system-index">SYSTEM {index + 1:02d}</span>'
            f"<h3>{escape(role_name)}</h3>"
            '<p class="story-shared">Same recorded weakness</p>'
            '<div class="story-surroundings"><span>Recorded surroundings</span>'
            f"<strong>{escape(surroundings)}</strong><p>{escape(usage)}</p></div>"
            f'<div class="story-outcome">{_band(score["band"])}<strong>{outcome}</strong></div>'
            '<details class="story-source"><summary>Supporting records</summary>'
            + evidence(score["host_ip"], "Stored score / host", False)
            + evidence(str(score["cve_id"]), "Stored score / shared vulnerability", False)
            + evidence(str(score["risk"]), "Stored score / risk", False)
            + evidence(str(role.get("evidence") or "none observed"), "Recorded role evidence")
            + evidence(quote, "Original finding evidence")
            + "</details></article>"
        )
    return (
        header + '<div class="story-provenance"><span class="stamp">' + kind + "</span>"
        f"<span>{note}</span></div>"
        '<div class="story-steps" role="group" aria-label="Example chapters">'
        '<button type="button" data-story-step="0" aria-pressed="true">01 <span>The warning</span></button>'
        '<button type="button" data-story-step="1" aria-pressed="false">02 <span>The setting</span></button>'
        '<button type="button" data-story-step="2" aria-pressed="false">03 <span>The priority</span></button></div>'
        '<div class="story-example" id="story-example" data-step="0">'
        '<div class="story-explanation" aria-live="polite">'
        '<div data-story-copy="0"><h3>One warning. Two different places.</h3>'
        "<p>These two systems have the same recorded weakness and base severity. "
        "A severity score alone does not describe their surroundings.</p></div>"
        '<div data-story-copy="1" hidden><h3>Now look at the surroundings.</h3>'
        "<p>What the system does, who can reach it, and observed protections add context. "
        "No protection observed does not mean no protection exists.</p></div>"
        '<div data-story-copy="2" hidden><h3>A priority should have a reason.</h3>'
        "<p>These are the priorities already stored for the two findings. The published "
        "formula scores them; the local model does not change their scores.</p></div></div>"
        '<div class="story-systems">' + "".join(systems) + "</div></div>"
        '<div class="story-controls"><button type="button" id="story-back" class="text-button" disabled>Back</button>'
        '<span id="story-position">1 of 3</span>'
        '<button type="button" id="story-next" class="primary-button">Add the context <span aria-hidden="true">&rarr;</span></button></div>'
        '<p class="story-caveat">This example explains the method. It is not an expert evaluation '
        "or a controlled comparison of historical feed snapshots.</p></section>"
    )


def _project_doors(payload: dict[str, Any] | None) -> str:
    header = (
        '<section id="project-doors" class="project-section project-doors" '
        'aria-labelledby="project-doors-title"><div class="doors-heading">'
        '<div class="project-section-heading"><span class="eyebrow">02 / THE RECORDED SYSTEM</span>'
        '<h2 id="project-doors-title">Every finding has a setting.</h2>'
        "<p>A weakness is only one part of the picture. The system around it gives "
        "the priority its meaning.</p></div>"
    )
    if payload is None or not payload["hosts"]:
        return (
            header
            + '</div><p class="story-absence">No recorded systems in this assessment.</p></section>'
        )
    profiles = {profile["host_ip"]: profile for profile in payload["context"]}
    scores = {score["finding_id"]: score for score in payload["scores"]}
    score_order = {identity: index for index, identity in enumerate(scores)}
    selected_host = (
        payload["scores"][0]["host_ip"] if payload["scores"] else payload["hosts"][0]["ip"]
    )
    options = "".join(
        f'<option value="{escape(host["ip"])}"'
        + (" selected" if host["ip"] == selected_host else "")
        + f">{escape(host['ip'])}</option>"
        for host in payload["hosts"]
    )
    synthetic = any("synthetic" in item["path"].lower() for item in payload["feeds_meta"]) or any(
        "synthetic" in item["provenance"]["raw_path"].lower() for item in payload["findings"]
    )
    kind = (
        "Synthetic records / not real-system findings"
        if synthetic
        else "Stored records / source evidence below"
    )
    panels: list[str] = []
    for host in payload["hosts"]:
        address = host["ip"]
        profile = profiles.get(address)
        role = profile["role"]["value"] if profile else "unknown"
        exposure = profile["exposure"]["value"] if profile else None
        findings = sorted(
            [finding for finding in payload["findings"] if finding["host_ip"] == address],
            key=lambda finding: score_order.get(finding["id"], len(scores)),
        )
        doors: list[str] = []
        details: list[str] = []
        for index, finding in enumerate(findings):
            identity = escape(finding["id"])
            score = scores.get(finding["id"])
            doors.append(
                f'<button class="project-door" type="button" data-project-door="{identity}" '
                f'aria-pressed="{str(index == 0).lower()}" aria-controls="door-record-{identity}" '
                f'aria-label="Inspect recorded finding: {escape(finding["title"])}">'
                + door(score["band"] if score else None, finding["id"])
                + f'<span class="door-index">Finding {index + 1:02d}</span></button>'
            )
            provenance = finding["provenance"]
            details.append(
                f'<article id="door-record-{identity}" class="door-record" '
                f'data-project-door-detail="{identity}"' + (" hidden" if index else "") + ">"
                '<span class="eyebrow">THE SELECTED FINDING</span>'
                f"<h3>{escape(finding['title'])}</h3>"
                '<div class="door-priority"><div><span>Recorded priority</span>'
                + _band(score["band"] if score else None)
                + "</div><div><strong>"
                + escape(_text(score["risk"] if score else None))
                + "</strong><span>Stored risk / 100</span></div></div>"
                f"<p>{escape(score['reason'] if score else 'No score is recorded for this finding.')}</p>"
                '<details class="door-source"><summary>Source evidence</summary>'
                + evidence(finding["evidence"], f"{finding['tool']} / verbatim finding")
                + evidence(provenance["raw_path"], "Raw artifact", False)
                + evidence(str(provenance["record_index"]), "Record index", False)
                + '</details><div class="door-links">'
                f'<a data-project-workflow data-workflow-node="canonical" data-workflow-finding="{identity}" '
                'href="/workflow#node=canonical">Trace this finding <span aria-hidden="true">&rarr;</span></a>'
                f'<a data-project-workflow data-workflow-node="score" data-workflow-finding="{identity}" '
                'href="/workflow#node=score">Inspect its score <span aria-hidden="true">&rarr;</span></a>'
                "</div></article>"
            )
        role_source = (
            f"{profile['role']['source']} / confidence {profile['role']['confidence']}"
            if profile
            else "No context profile recorded"
        )
        panels.append(
            f'<div class="doors-layout" data-project-door-host="{escape(address)}"'
            + (" hidden" if address != selected_host else "")
            + ">"
            '<figure class="doors-scene"><div class="doors-system">'
            + building(role)
            + '<div class="doors-system-caption"><span class="eyebrow">RECORDED SYSTEM</span>'
            f"<strong>{escape(str(role).replace('_', ' '))}</strong>"
            f"<span>{escape(address)}</span><small>{escape(role_source)}</small></div></div>"
            '<div class="doors-setting"><span>Exposure</span>'
            f"<strong>{escape(_text(exposure).replace('_', ' '))}</strong>"
            f"<span>{len(findings)} recorded {'finding' if len(findings) == 1 else 'findings'}</span></div>"
            '<div class="doors-findings" role="group" aria-label="Recorded finding doors">'
            + (
                "".join(doors)
                or '<p class="story-absence">No findings recorded for this system.</p>'
            )
            + '</div><p class="doors-key">System = building. Finding = door. Colour = stored priority.</p>'
            '</figure><div class="doors-records">' + "".join(details) + "</div></div>"
        )
    return (
        header + '<label class="project-host-choice" for="project-doors-target">Recorded system'
        f'<select id="project-doors-target" data-project-host>{options}</select></label></div>'
        f'<p class="doors-provenance">{kind}</p>'
        + "".join(panels)
        + '<p class="doors-caveat">The drawings are symbolic. A finding is not proof of an exploitable '
        "entrance, and an unknown role does not mean an unimportant system.</p></section>"
    )


def render_workbench(
    template: str,
    payload: dict[str, Any] | None,
    runs: list[dict[str, Any]],
    config: dict[str, Any],
) -> str:
    if payload is None:
        options = "".join(
            f'<option value="{escape(run["run_id"])}">{escape(run["run_id"])}</option>'
            for run in runs
        )
        content = (
            '<section class="stage-panel" id="stage-evidence" data-panel="evidence">'
            + _heading("ASSESSMENT", "Begin with a recorded run.", "No scan starts here.")
            + (
                f'<label class="run-choice">Stored run<select id="select-run"><option value="">Choose an assessment</option>{options}</select></label>'
                if runs
                else '<div class="state-message"><span class="stamp">NO RUNS</span><p>Import an authorized capture through the CLI, then refresh.</p></div>'
            )
            + "</section>"
        )
        strip = ""
        boot = {"assessment": None, "configuration": config, "runs": runs}
    else:
        content = (
            _evidence_stage(payload, config)
            + _context_stage(payload, config)
            + _risk_stage(payload, config)
            + _priorities_stage(payload)
        )
        quotations = "".join(evidence(text, source) for text, source in evidence_items(payload))
        content += (
            '<details class="archive all-evidence"><summary>Complete source evidence ledger</summary>'
            + quotations
            + "</details>"
            + _inspector(payload)
        )
        strip = run_strip(payload)
        synthetic = any(
            "synthetic" in item["path"].lower() for item in payload["feeds_meta"]
        ) or any(
            "synthetic" in item["provenance"]["raw_path"].lower() for item in payload["findings"]
        )
        kind = "SYNTHETIC" if synthetic else "SOURCE UNLABELLED"
        strip = strip.replace(
            "<span>Run provenance</span>",
            f'<span class="stamp">{kind}</span><span>Run provenance</span>',
        )
        pair = _pair(payload)
        boot = {
            "assessment": payload,
            "configuration": config,
            "runs": runs,
            "tour_finding": pair[0]["finding_id"] if pair else None,
        }
    serialized = (
        json.dumps(boot, sort_keys=True, ensure_ascii=True, allow_nan=False)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
    document = template.replace(
        '<main id="notebook"></main>', f'<main id="notebook">{content}</main>'
    )
    document = document.replace(
        '<div id="project-story-slot"></div>', _project_story(payload, runs)
    )
    document = document.replace('<div id="project-doors-slot"></div>', _project_doors(payload))
    document = document.replace('<div id="run-strip-slot"></div>', strip)
    run_choice = ""
    if payload is not None:
        run_options = "".join(
            f'<option value="{escape(run["run_id"])}"'
            + (" selected" if run["run_id"] == payload["run"]["run_id"] else "")
            + f">{escape(run['run_id'])}</option>"
            for run in runs or [payload["run"]]
        )
        run_choice = (
            '<label class="header-run"><span>Assessment</span>'
            f'<select id="select-run">{run_options}</select></label>'
        )
    document = document.replace('<div id="run-choice-slot"></div>', run_choice)
    return document.replace(
        "</body>",
        f'<script id="assessment-data" type="application/json">{serialized}</script></body>',
    )
