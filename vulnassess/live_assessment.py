"""One explicit, bounded live target run for the loopback workbench."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from vulnassess import analyst, context
from vulnassess.errors import ConfigError
from vulnassess.readers import parse_nmap_xml
from vulnassess.settings import Settings

Progress = Callable[[str, str, str], None]


def nmap_binary() -> str | None:
    configured = os.environ.get("VULNASSESS_NMAP_BIN", "nmap")
    return shutil.which(configured)


def run(
    target: str,
    check: dict[str, Any],
    config_dir: Path,
    *,
    provider: str,
    on_progress: Progress,
    on_capture: Callable[[dict[str, Any]], None] | None = None,
    on_case: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Scan one scoped, DNS-pinned IP and analyze its in-memory evidence."""
    if provider not in ("ollama", "openrouter", "groq"):
        raise ConfigError("Unknown analyst provider")
    addresses = check.get("resolved_ips") or []
    if check.get("status") not in ("ready", "needs-tools", "needs-pinning") or len(addresses) != 1:
        raise ConfigError(check.get("reason") or "Target must resolve to one authorised address")
    target_ip = addresses[0]
    settings = Settings(config_dir)
    if settings.scope.is_canary(target_ip) or not settings.scope.contains(target_ip):
        raise ConfigError("Target is outside the authorised scope")
    binary = nmap_binary()
    if binary is None:
        raise ConfigError("Nmap is not installed or VULNASSESS_NMAP_BIN is not configured")
    on_progress("scope", "complete", f"{target} pinned to authorised {target_ip}")
    on_progress("scanner", "running", "Nmap: common 100 TCP ports, light service detection")
    with TemporaryDirectory(prefix="vulnassess-live-") as directory:
        capture = Path(directory) / "nmap.xml"
        command = [
            binary,
            "-n",
            "-Pn",
            "-sT",
            "--top-ports",
            "100",
            "-sV",
            "--version-light",
            "-T3",
            "-oX",
            str(capture),
            target_ip,
        ]
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, timeout=180, check=False
            )
        except subprocess.TimeoutExpired as error:
            raise ConfigError("Light Nmap scan timed out after 180 seconds") from error
        if completed.returncode != 0 or not capture.is_file():
            raise ConfigError(f"Light Nmap scan failed (exit {completed.returncode})")
        hosts, findings = parse_nmap_xml(capture, "live")
    matching = [host for host in hosts if host.ip == target_ip]
    if len(matching) != 1:
        raise ConfigError("Nmap did not return exactly the pinned target")
    host = matching[0]
    on_progress(
        "scanner",
        "complete",
        f"{len(host.services)} open services; {len(findings)} vulnerability findings",
    )
    if on_capture is not None:
        on_capture(
            {
                "target": target,
                "resolved_ip": target_ip,
                "services": [service.to_json() for service in host.services],
                "finding_count": len(findings),
            }
        )
    on_progress("context", "running", "Inferring context from the observed services")
    profile = context.build_profile(
        host, findings, settings.scope, settings.roles, settings.controls
    )
    on_progress(
        "context", "complete", f"Role {profile.role.value}; exposure {profile.exposure.value}"
    )
    payload = {
        "hosts": [host.to_json()],
        "findings": [finding.to_json() for finding in findings],
        "scores": [],
        "enrichments": [],
        "context": [profile.to_json()],
        "scanner_coverage": {
            "nmap": "top 100 TCP ports, light service detection",
            "nikto": "not run; separate authorized web scan required",
            "nessus": "no .nessus report imported; no Nessus scan claimed",
        },
    }
    model_case, _, _ = analyst.build_case(payload, target_ip)
    decision_frame = analyst.build_decision_frame(model_case)
    if on_capture is not None:
        on_capture(
            {
                "target": target,
                "resolved_ip": target_ip,
                "services": [service.to_json() for service in host.services],
                "finding_count": len(findings),
                "decision_frame": decision_frame,
            }
        )
    if on_case is not None:
        on_case(
            {
                "target": target,
                "resolved_ip": target_ip,
                "scan_profile": "Nmap top 100 TCP ports, light service detection",
                "services": [service.to_json() for service in host.services],
                "finding_count": len(findings),
                "decision_frame": decision_frame,
                "payload": payload,
            }
        )
    result = analyst.analyze_target(payload, target_ip, provider=provider, on_progress=on_progress)
    return {
        "target": target,
        "resolved_ip": target_ip,
        "scan_profile": "Nmap top 100 TCP ports, light service detection",
        "services": [service.to_json() for service in host.services],
        "finding_count": len(findings),
        "decision_frame": decision_frame,
        "analyst": result,
    }
