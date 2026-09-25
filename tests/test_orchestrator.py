"""Nmap-first orchestration tests with an injected scanner executor."""

import io
import json
import shutil
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from vulnassess.cli import main
from vulnassess.errors import AdapterError, ConfigError, ScopeError
from vulnassess.orchestrator import (
    Execution,
    ScannerCommand,
    check_canary_log,
    derive_endpoints,
    execute_local,
    missing_binaries,
    orchestrate,
    plan,
    web_plan,
)
from vulnassess.schema import Host, Service
from vulnassess.settings import Settings
from vulnassess.store import Store

ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC = ROOT / "tests" / "synthetic"
SETTINGS = Settings(ROOT / "config")


def service(port: int, name: str, *, tls: bool = False) -> Service:
    return Service(
        port=port,
        protocol="tcp",
        name=name,
        banner=f"{port}/tcp {name}",
        tls=tls,
    )


class FakeExecutor:
    def __init__(self, fail: set[str] | None = None, nmap_source: Path | None = None):
        self.fail = fail or set()
        self.nmap_source = nmap_source or SYNTHETIC / "synthetic_nmap_two_machines.xml"
        self.calls = []

    def __call__(self, command):
        self.calls.append(command)
        if command.tool in self.fail:
            return Execution(7, "2026-09-07T00:00:00Z", "2026-09-07T00:00:01Z", "synthetic failure")
        source = {
            "nmap": self.nmap_source,
            "nikto": SYNTHETIC / "synthetic_nikto_dvwa.json",
        }[command.tool]
        command.output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, command.output)
        return Execution(0, "2026-09-07T00:00:00Z", "2026-09-07T00:00:01Z")


class TestOrchestrator(unittest.TestCase):
    def test_scan_cli_plans_only_nmap_and_never_creates_output(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "captures"
            stdout = io.StringIO()
            with (
                patch("vulnassess.orchestrator.shutil.which", return_value=None),
                redirect_stdout(stdout),
            ):
                code = main(
                    [
                        "--config",
                        str(ROOT / "config"),
                        "scan",
                        "--run-id",
                        "synthetic-plan",
                        "--target-ip",
                        "172.28.0.10",
                        "--tool",
                        "nikto",
                        "--out-dir",
                        str(output),
                        "--json",
                    ]
                )
            result = json.loads(stdout.getvalue())

        self.assertEqual(code, 0)
        self.assertFalse(result["executed"])
        self.assertEqual(result["notice"], "not run by the agent")
        self.assertEqual(result["plan"]["discovery"]["tool"], "nmap")
        self.assertEqual(result["plan"]["web_tools"], ["nikto"])
        self.assertEqual(result["missing"], ["nmap", "nikto"])
        self.assertFalse(output.exists())

    def test_scan_cli_execute_uses_injected_nmap_first_path(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "captures"
            database = root / "synthetic_scan.db"
            canary = root / "synthetic_canary.log"
            canary.write_text("", encoding="utf-8")
            executor = FakeExecutor()
            stdout = io.StringIO()
            with (
                patch("vulnassess.cli.orchestrator.missing_binaries", return_value=[]),
                patch(
                    "vulnassess.cli.orchestrator.execute_local",
                    side_effect=lambda command, timeout: executor(command),
                ),
                redirect_stdout(stdout),
            ):
                code = main(
                    [
                        "--db",
                        str(database),
                        "--config",
                        str(ROOT / "config"),
                        "scan",
                        "--run-id",
                        "synthetic-execute",
                        "--target-ip",
                        "172.28.0.10",
                        "--out-dir",
                        str(output),
                        "--canary-log",
                        str(canary),
                        "--execute",
                        "--json",
                    ]
                )
            result = json.loads(stdout.getvalue())
            self.assertTrue(database.is_file(), "executed captures must reach the store")
            with Store(database) as store:
                hosts = store.hosts("synthetic-execute")
                findings = store.findings("synthetic-execute")
                summary = store.run_info("synthetic-execute")["summary"]
            self.assertEqual([host.ip for host in hosts], ["172.28.0.10"])
            self.assertTrue(hosts[0].services)
            self.assertEqual({finding.tool for finding in findings}, {"nmap", "nikto"})
            self.assertTrue(
                all(Path(finding.provenance.raw_path).is_file() for finding in findings)
            )
            self.assertEqual(summary["scans"][-1], result)

        self.assertEqual(code, 0)
        self.assertEqual([call.tool for call in executor.calls], ["nmap", "nikto"])
        self.assertTrue(result["executed"])
        self.assertTrue(result["complete"])
        self.assertEqual(result["canary_evidence"]["status"], "VERIFIED")
        self.assertEqual(result["canary_evidence_after"]["status"], "VERIFIED")

    def test_scan_cli_refuses_execute_when_a_binary_is_missing(self):
        errors = io.StringIO()
        with (
            patch("vulnassess.cli.orchestrator.missing_binaries", return_value=["nmap"]),
            patch("vulnassess.cli.orchestrator.execute_local") as execute,
            redirect_stdout(io.StringIO()),
            redirect_stderr(errors),
        ):
            code = main(
                [
                    "--config",
                    str(ROOT / "config"),
                    "scan",
                    "--run-id",
                    "synthetic-missing",
                    "--target-ip",
                    "172.28.0.10",
                    "--execute",
                ]
            )

        self.assertEqual(code, 2)
        execute.assert_not_called()
        self.assertIn("MISSING scanner binary", errors.getvalue())

    def test_scan_cli_persists_partial_and_failed_runs(self) -> None:
        for target, failed, expected_tools in (
            ("172.28.0.10", {"nikto"}, {"nmap"}),
            ("172.28.0.10", {"nmap"}, set()),
            ("172.28.0.11", set(), set()),
        ):
            with self.subTest(target=target, failed=failed), TemporaryDirectory() as directory:
                root = Path(directory)
                database = root / "synthetic_partial.db"
                canary = root / "synthetic_canary.log"
                canary.write_text("", encoding="utf-8")
                executor = FakeExecutor(fail=failed)
                stdout = io.StringIO()
                with (
                    patch("vulnassess.cli.orchestrator.missing_binaries", return_value=[]),
                    patch(
                        "vulnassess.cli.orchestrator.execute_local",
                        side_effect=lambda command, timeout: executor(command),
                    ),
                    redirect_stdout(stdout),
                ):
                    code = main(
                        [
                            "--db",
                            str(database),
                            "--config",
                            str(ROOT / "config"),
                            "scan",
                            "--run-id",
                            "synthetic-partial",
                            "--target-ip",
                            target,
                            "--out-dir",
                            str(root / "captures"),
                            "--canary-log",
                            str(canary),
                            "--execute",
                            "--json",
                        ]
                    )
                result = json.loads(stdout.getvalue())
                self.assertEqual(code, AdapterError.exit_code)
                self.assertFalse(result["complete"])
                self.assertTrue(database.is_file())
                with Store(database) as store:
                    self.assertEqual(
                        {finding.tool for finding in store.findings("synthetic-partial")},
                        expected_tools,
                    )
                    self.assertEqual(
                        store.run_info("synthetic-partial")["summary"]["scans"][-1], result
                    )
                    if not expected_tools:
                        self.assertEqual(store.hosts("synthetic-partial"), [])

    def test_local_executor_is_shell_free_bounded_and_mocked(self):
        command = ScannerCommand("nmap", ("nmap", "127.0.0.1"), Path("synthetic.xml"))
        completed = SimpleNamespace(
            returncode=0,
            stderr="synthetic\x00detail" + "x" * 3000,
            stdout="",
        )
        with patch("vulnassess.orchestrator.subprocess.run", return_value=completed) as run:
            execution = execute_local(command, timeout=30)

        self.assertEqual(execution.exit_code, 0)
        self.assertNotIn("\x00", execution.detail)
        self.assertEqual(len(execution.detail), 2048)
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertFalse(run.call_args.kwargs["check"])
        self.assertEqual(run.call_args.kwargs["timeout"], 30)
        with self.assertRaises(ConfigError):
            execute_local(command, timeout=0)

    def test_binary_check_always_includes_mandatory_nmap(self):
        with patch("vulnassess.orchestrator.shutil.which", return_value=None):
            missing = missing_binaries(("nikto",))
        self.assertEqual(missing, ["nmap", "nikto"])

    def test_scope_and_canary_are_rejected_before_output_or_execution(self):
        for target in ("8.8.8.8", "172.28.0.250", "portal.example.edu"):
            with self.subTest(target=target), TemporaryDirectory() as directory:
                output = Path(directory) / "captures"
                with self.assertRaises(ScopeError):
                    plan(SETTINGS, target, output)
                self.assertFalse(output.exists())

    def test_explicitly_authorised_cidr_does_not_require_a_demo_target_name(self):
        with TemporaryDirectory() as directory:
            scan_plan = plan(
                SETTINGS, "192.168.0.116", Path(directory) / "captures", tools=("nmap",)
            )
            self.assertEqual(scan_plan.target_ip, "192.168.0.116")
            self.assertEqual(scan_plan.discovery.argv[-1], "192.168.0.116")
            self.assertFalse((Path(directory) / "captures").exists())

    def test_discovery_derives_only_observed_http_endpoints(self):
        host = Host(
            ip="172.28.0.11",
            services=(
                service(22, "ssh"),
                service(80, "http"),
                service(443, "https", tls=True),
                service(8443, "ssl/http", tls=True),
                service(3306, "mysql"),
            ),
        )

        endpoints = derive_endpoints(host)

        self.assertEqual(
            [endpoint.url for endpoint in endpoints],
            [
                "http://172.28.0.11",
                "https://172.28.0.11",
                "https://172.28.0.11:8443",
            ],
        )
        self.assertEqual(
            [endpoint.evidence for endpoint in endpoints],
            ["80/tcp http", "443/tcp https", "8443/tcp ssl/http"],
        )

    def test_no_web_service_records_explicit_web_tool_skips(self):
        with TemporaryDirectory() as directory:
            scan_plan = plan(SETTINGS, "172.28.0.10", Path(directory) / "captures")
            commands, skips = web_plan(
                scan_plan,
                Host(ip="172.28.0.10", services=(service(22, "ssh"),)),
            )

        self.assertEqual(commands, [])
        self.assertEqual([item.tool for item in skips], ["nikto"])
        self.assertTrue(all("no HTTP service" in item.skip_reason for item in skips))

    def test_successful_run_is_nmap_first_and_records_every_outcome(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "captures"
            empty_log = Path(directory) / "synthetic_canary.log"
            empty_log.write_text("", encoding="utf-8")
            scan_plan = plan(
                SETTINGS,
                "172.28.0.10",
                output,
                tools=("nmap", "nikto"),
                canary_log=empty_log,
            )
            executor = FakeExecutor()

            result = orchestrate(scan_plan, "synthetic-run", executor)

        self.assertEqual([call.tool for call in executor.calls], ["nmap", "nikto"])
        self.assertEqual(result["canary_evidence"]["status"], "VERIFIED")
        self.assertEqual(result["successful_tools"], 2)
        self.assertEqual(result["failed_tools"], 0)
        self.assertEqual(result["skipped_tools"], 0)
        self.assertTrue(result["complete"])
        self.assertEqual(result["endpoints"][0]["url"], "http://172.28.0.10")
        self.assertEqual([item["status"] for item in result["outcomes"]], ["success"] * 2)
        self.assertTrue(all(item["started_at"] for item in result["outcomes"]))
        self.assertTrue(all(item["raw_path"] for item in result["outcomes"]))

    def test_web_tool_failure_does_not_hide_other_tool_success(self):
        with TemporaryDirectory() as directory:
            scan_plan = plan(SETTINGS, "172.28.0.10", Path(directory) / "captures")
            executor = FakeExecutor(fail={"nikto"})

            result = orchestrate(scan_plan, "synthetic-run", executor)

        outcomes = {item["tool"]: item for item in result["outcomes"]}
        self.assertEqual(outcomes["nmap"]["status"], "success")
        self.assertEqual(outcomes["nikto"]["status"], "failed")
        self.assertEqual(outcomes["nikto"]["exit_code"], 7)
        self.assertEqual(result["failed_tools"], 1)
        self.assertFalse(result["complete"])

    def test_discovery_failure_skips_every_web_tool(self):
        with TemporaryDirectory() as directory:
            scan_plan = plan(SETTINGS, "172.28.0.10", Path(directory) / "captures")
            executor = FakeExecutor(fail={"nmap"})

            result = orchestrate(scan_plan, "synthetic-run", executor)

        self.assertEqual([call.tool for call in executor.calls], ["nmap"])
        self.assertEqual(result["failed_tools"], 1)
        self.assertEqual(result["skipped_tools"], 1)
        self.assertTrue(
            all("discovery failed" in item["skip_reason"] for item in result["outcomes"][1:])
        )

    def test_successful_ssh_only_discovery_skips_web_tools(self):
        with TemporaryDirectory() as directory:
            scan_plan = plan(SETTINGS, "172.28.0.10", Path(directory) / "captures")
            executor = FakeExecutor(nmap_source=SYNTHETIC / "synthetic_nmap_ssh_only.xml")

            result = orchestrate(scan_plan, "synthetic-run", executor)

        self.assertEqual([call.tool for call in executor.calls], ["nmap"])
        self.assertEqual(result["successful_tools"], 1)
        self.assertEqual(result["skipped_tools"], 1)
        self.assertEqual(result["endpoints"], [])
        self.assertTrue(result["complete"])

    def test_discovery_without_requested_host_is_not_complete(self):
        for tools in (("nmap",), ("nmap", "nikto")):
            with self.subTest(tools=tools), TemporaryDirectory() as directory:
                scan_plan = plan(
                    SETTINGS,
                    "172.28.0.11",
                    Path(directory) / "captures",
                    tools=tools,
                )
                executor = FakeExecutor()

                result = orchestrate(scan_plan, "synthetic-missing-host", executor)

            self.assertEqual([call.tool for call in executor.calls], ["nmap"])
            self.assertFalse(result["complete"])
            self.assertEqual(result["successful_tools"], 0)
            self.assertEqual(result["failed_tools"], 1)
            discovery = result["outcomes"][0]
            self.assertEqual(discovery["status"], "failed")
            self.assertEqual(discovery["exit_code"], 0)
            self.assertIn("172.28.0.11", discovery["failure"])
            self.assertTrue(discovery["raw_path"])

    def test_canary_log_is_missing_empty_or_a_hard_failure(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "synthetic_missing.log"
            empty = root / "synthetic_empty.log"
            nonempty = root / "synthetic_nonempty.log"
            empty.write_text("", encoding="utf-8")
            nonempty.write_text("request observed", encoding="utf-8")

            self.assertEqual(check_canary_log(None)["status"], "MISSING")
            self.assertEqual(check_canary_log(missing)["status"], "MISSING")
            self.assertEqual(check_canary_log(empty)["status"], "VERIFIED")
            with self.assertRaises(ScopeError):
                check_canary_log(nonempty)


if __name__ == "__main__":
    unittest.main(verbosity=2)
