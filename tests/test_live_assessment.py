"""The live path uses one authorised IP and a bounded scanner command."""

import sqlite3
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from vulnassess import live_assessment
from vulnassess.errors import ConfigError
from vulnassess.ui.server import UiApplication

ROOT = Path(__file__).resolve().parents[1]


def test_live_scan_uses_pinned_ip_and_sends_fresh_services_to_analyst():
    check = {"status": "needs-pinning", "resolved_ips": ["45.33.32.156"]}
    events = []
    captures = []

    def fake_nmap(command, **kwargs):
        assert command[-1] == "45.33.32.156"
        assert command[1:4] == ["-n", "-Pn", "-sT"]
        assert command[command.index("--top-ports") + 1] == "100"
        assert "--script" not in command
        Path(command[command.index("-oX") + 1]).write_text(
            '<nmaprun start="1"><host><status state="up"/>'
            '<address addr="45.33.32.156" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="22"><state state="open"/>'
            '<service name="ssh" product="OpenSSH" version="6.6"/></port></ports>'
            "</host></nmaprun>",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    def fake_analyst(payload, host_ip, **kwargs):
        assert host_ip == "45.33.32.156"
        assert payload["hosts"][0]["services"][0]["port"] == 22
        assert payload["findings"] == []
        assert payload["scores"] == []
        assert payload["scanner_coverage"] == {
            "nmap": "top 100 TCP ports, light service detection",
            "nikto": "not run; separate authorized web scan required",
            "nessus": "no .nessus report imported; no Nessus scan claimed",
        }
        assert kwargs["provider"] == "openrouter"
        return {"host_ip": host_ip, "analysis": {"summary": "SSH observed."}}

    with (
        patch.object(live_assessment, "nmap_binary", return_value="nmap.exe"),
        patch.object(live_assessment.subprocess, "run", side_effect=fake_nmap),
        patch.object(live_assessment.analyst, "analyze_target", side_effect=fake_analyst),
    ):
        result = live_assessment.run(
            "scanme.nmap.org",
            check,
            ROOT / "config",
            provider="openrouter",
            on_progress=lambda *event: events.append(event),
            on_capture=captures.append,
        )
    assert result["resolved_ip"] == "45.33.32.156"
    assert result["services"][0]["port"] == 22
    assert captures[0]["finding_count"] == 0
    assert captures[-1]["decision_frame"]["mode"] == "verification_only"
    assert captures[-1]["decision_frame"]["context"]["exposure"]["value"] == "internet_facing"
    assert captures[-1]["decision_frame"]["priorities"] == []
    assert result["decision_frame"] == captures[-1]["decision_frame"]
    assert ("scanner", "complete") in [(stage, state) for stage, state, _ in events]


def test_live_scan_refuses_out_of_scope_ip_before_launch():
    with patch.object(
        live_assessment.subprocess, "run", side_effect=AssertionError("scanner launched")
    ):
        with pytest.raises(ConfigError, match="outside the authorised scope"):
            live_assessment.run(
                "8.8.8.8",
                {"status": "ready", "resolved_ips": ["8.8.8.8"]},
                ROOT / "config",
                provider="openrouter",
                on_progress=lambda *_: None,
            )


def test_model_retry_reuses_recent_scan_without_starting_nmap(tmp_path):
    database = tmp_path / "vulnassess.db"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE runs (run_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, "
            "config_hash TEXT NOT NULL, summary_json TEXT NOT NULL DEFAULT '{}')"
        )
    app = UiApplication(database, ROOT / "config")
    check = {"status": "ready", "resolved_ips": ["45.33.32.156"], "missing": []}
    events = []
    captures = []
    case = {
        "target": "scanme.nmap.org",
        "resolved_ip": "45.33.32.156",
        "scan_profile": "light",
        "services": [{"port": 22}],
        "finding_count": 0,
        "payload": {
            "hosts": [{"ip": "45.33.32.156"}],
            "findings": [],
            "scores": [],
            "enrichments": [],
            "context": [],
        },
    }

    def first_run(*args, **kwargs):
        kwargs["on_case"](case)
        raise RuntimeError("model unavailable")

    with (
        patch.object(app, "target_check", return_value=check),
        patch("vulnassess.ui.server.time.monotonic", return_value=100),
        patch("vulnassess.ui.server.live_assessment.run", side_effect=first_run) as scanner,
        patch(
            "vulnassess.ui.server.analyst.analyze_target",
            return_value={"analysis": {"summary": "SSH observed"}},
        ),
    ):
        with pytest.raises(RuntimeError, match="model unavailable"):
            app.live_report(
                "scanme.nmap.org",
                "openrouter",
                lambda *event: events.append(event),
                captures.append,
            )
        with pytest.raises(ConfigError, match="Choose re-analyze recent evidence"):
            app.live_report(
                "scanme.nmap.org",
                "openrouter",
                lambda *event: events.append(event),
                captures.append,
            )
        result = app.live_report(
            "scanme.nmap.org",
            "openrouter",
            lambda *event: events.append(event),
            captures.append,
            reuse_recent=True,
        )

    assert scanner.call_count == 1
    assert result["reused_scan"] is True
    assert result["services"] == [{"port": 22}]
    assert captures[-1]["services"] == [{"port": 22}]
    assert any(stage == "scanner" and "Reused" in detail for stage, _, detail in events)
