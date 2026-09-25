"""The whole test suite. Run with: python -m unittest tests.test_all -v

Synthetic inputs live in tests/synthetic/ and are never evidence that a parser, feed or
score works on real data. Real captures are gated behind a skip until a human provides them.
"""

import io
import json
import re
import socket
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import yaml

from vulnassess import (
    context,
    cvss31,
    diff,
    evaluate,
    explain,
    intel,
    pipeline,
    runner,
    scoring,
)
from vulnassess.cli import main
from vulnassess.errors import (
    AdapterError,
    ConfigError,
    IntelUnavailable,
    LLMUnavailable,
    ScopeError,
)
from vulnassess.readers import parse_nikto_json, parse_nmap_xml, parse_zap_json
from vulnassess.schema import (
    ContextProfile,
    Enrichment,
    Feature,
    Finding,
    Host,
    Provenance,
    Service,
)
from vulnassess.settings import Settings
from vulnassess.store import Store

ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC = ROOT / "tests" / "synthetic"
FIXTURES = ROOT / "tests" / "fixtures"
NMAP_SYNTH = SYNTHETIC / "synthetic_nmap_two_machines.xml"
ZAP_SYNTH = SYNTHETIC / "synthetic_zap_dvwa.json"
NIKTO_SYNTH = SYNTHETIC / "synthetic_nikto_dvwa.json"
FEEDS_SYNTH = SYNTHETIC / "feeds"
BASE_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

SETTINGS = Settings(ROOT / "config")
WEIGHTS = SETTINGS.weights
ROLES = SETTINGS.roles
CONTROLS = SETTINGS.controls

_REAL_CONNECT = socket.socket.connect


def setUpModule() -> None:
    def forbidden(*_args, **_kwargs):
        raise AssertionError("network access is forbidden in tests")

    socket.socket.connect = forbidden


def tearDownModule() -> None:
    socket.socket.connect = _REAL_CONNECT


# --------------------------------------------------------------------------- helpers
def make_host(ip: str = "172.28.0.10", os_guess: str | None = None, **services) -> Host:
    return Host(ip=ip, hostname=None, os_guess=os_guess, services=tuple(services.get("items", ())))


def service(port: int, name: str, banner: str, **kwargs) -> Service:
    return Service(
        port=port,
        protocol=kwargs.get("protocol", "tcp"),
        name=name,
        product=kwargs.get("product"),
        version=kwargs.get("version"),
        cpe=kwargs.get("cpe"),
        banner=banner,
        tls=kwargs.get("tls", False),
    )


def make_finding(**kwargs) -> Finding:
    defaults = dict(
        host_ip="172.28.0.10",
        port=80,
        protocol="tcp",
        url=None,
        tool="nmap",
        tool_native_id="vulners:CVE-1999-9001",
        title="vulners reports CVE-1999-9001 on http",
        description="synthetic",
        evidence="CVE-1999-9001  9.8",
        cve_ids=["CVE-1999-9001"],
        first_seen="2026-09-05T00:00:00+00:00",
        last_seen="2026-09-05T00:00:00+00:00",
        provenance=Provenance("nmap", "tests/synthetic/x.xml", 1, "unit"),
    )
    defaults.update(kwargs)
    return Finding.make(**defaults)


def make_enrichment(**kwargs) -> Enrichment:
    defaults = dict(
        finding_id="f-1",
        cve_id="CVE-1999-9001",
        match_method="explicit",
        match_confidence=1.0,
        cvss31_vector=BASE_VECTOR,
        cvss31_base=9.8,
        epss=0.94321,
        epss_percentile=0.9987,
        kev=True,
        kev_date_added="2021-11-03",
        patch_references=("https://example.invalid/patch",),
        version_end="2.4.51",
        feed_dates={"nvd": "2026-09-05"},
    )
    defaults.update(kwargs)
    return Enrichment(**defaults)


def make_profile(**kwargs) -> ContextProfile:
    role = kwargs.get("role", "web_frontend")
    exposure = kwargs.get("exposure", "internal")
    manual: dict[str, Feature] = {}
    if kwargs.get("environment"):
        manual["environment"] = Feature(
            kwargs["environment"], 1.0, "manual", "scope.yaml tags.environment"
        )
    if kwargs.get("criticality"):
        manual["criticality"] = Feature(
            kwargs["criticality"], 1.0, "manual", "scope.yaml tags.criticality"
        )
    controls = {
        "waf": Feature(
            kwargs.get("waf", False) or False,
            0.75 if kwargs.get("waf") else 0.5,
            "rule",
            kwargs.get("waf_evidence", "none observed"),
        ),
        "auth_required": Feature(kwargs.get("auth", False), 0.5, "rule", "none observed"),
        "tls": Feature(False, 0.5, "rule", "none observed"),
        "rate_limiting": Feature(False, 0.5, "rule", "none observed"),
    }
    return ContextProfile(
        host_ip=kwargs.get("host_ip", "172.28.0.10"),
        role=Feature(role, kwargs.get("role_confidence", 0.9), "rule", "80/tcp http"),
        exposure=Feature(
            exposure, kwargs.get("exposure_confidence", 0.85), "rule", f"ip is {exposure}"
        ),
        segment=kwargs.get("segment", "172.28.0.10/32"),
        controls=controls,
        manual=manual,
    )


def temp_store(directory: str) -> Store:
    return Store(Path(directory) / "data" / "vulnassess.db")


# --------------------------------------------------------------------------- CVSS (5)
class TestCvss31(unittest.TestCase):
    PINNED = {
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N": 3.7,
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.6,
    }

    def test_pinned_base_scores_match_the_official_calculator(self):
        for vector, expected in self.PINNED.items():
            with self.subTest(vector=vector):
                self.assertEqual(cvss31.base_score(cvss31.parse(vector)), expected)

    def test_environmental_equals_base_when_nothing_is_modified(self):
        for vector, expected in self.PINNED.items():
            with self.subTest(vector=vector):
                metrics = cvss31.parse(vector)
                self.assertEqual(cvss31.environmental_score(metrics), expected)

    def test_modified_attack_vector_lowers_the_environmental_score(self):
        metrics = cvss31.parse(BASE_VECTOR)
        metrics["MAV"] = "A"
        self.assertEqual(cvss31.environmental_score(metrics), 8.8)

    def test_high_requirements_never_fall_below_the_base_score(self):
        metrics = cvss31.parse(BASE_VECTOR)
        metrics.update({"CR": "H", "IR": "H", "AR": "H"})
        self.assertGreaterEqual(cvss31.environmental_score(metrics), 9.8)

    def test_a_cvss40_vector_is_rejected(self):
        with self.assertRaises(ValueError):
            cvss31.parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")


# --------------------------------------------------------------------------- scoring (10)
class TestScoring(unittest.TestCase):
    def test_two_machine_golden(self):
        finding = make_finding()
        enrichment = make_enrichment(finding_id=finding.id)
        internal = make_profile(
            role="web_frontend", exposure="internal", environment="test", host_ip="172.28.0.10"
        )
        exposed = make_profile(
            role="database", exposure="internet_facing", host_ip="172.28.0.12", segment=None
        )

        low = scoring.score(finding, enrichment, internal, (), WEIGHTS)
        high = scoring.score(finding, enrichment, exposed, (), WEIGHTS)
        print("\n  machine A:", json.dumps(low.to_json(), sort_keys=True))
        print("  machine B:", json.dumps(high.to_json(), sort_keys=True))

        self.assertEqual(low.base_score, high.base_score)
        self.assertEqual(high.band, "Critical")
        self.assertGreaterEqual(high.risk, 90)
        self.assertLess(low.risk, high.risk)
        self.assertNotEqual(low.band, "Critical")
        self.assertIn("internal", low.reason)
        self.assertIn("internet-facing database", high.reason)
        self.assertIn("KEV", high.reason)

    def test_kev_never_lowers_risk(self):
        for percentile in (None, 0.0, 0.3, 0.9):
            with self.subTest(percentile=percentile):
                without, _ = scoring.risk(6.9, percentile, False, None, WEIGHTS, False)
                with_kev, _ = scoring.risk(6.9, percentile, True, None, WEIGHTS, False)
                self.assertGreaterEqual(with_kev, without)

    def test_higher_epss_never_lowers_risk(self):
        previous = -1.0
        for percentile in (0.0, 0.1, 0.5, 0.9, 1.0):
            value, _ = scoring.risk(7.5, percentile, False, None, WEIGHTS, False)
            self.assertGreaterEqual(value, previous)
            previous = value

    def test_internet_facing_is_never_ranked_below_internal(self):
        finding = make_finding()
        enrichment = make_enrichment(finding_id=finding.id)
        for role in WEIGHTS["environmental"]["role_requirements"]:
            with self.subTest(role=role):
                internal = scoring.score(
                    finding, enrichment, make_profile(role=role, exposure="internal"), (), WEIGHTS
                )
                exposed = scoring.score(
                    finding,
                    enrichment,
                    make_profile(role=role, exposure="internet_facing"),
                    (),
                    WEIGHTS,
                )
                self.assertGreaterEqual(exposed.risk, internal.risk)

    def test_missing_epss_is_unscored_not_defaulted(self):
        finding = make_finding()
        enrichment = make_enrichment(
            finding_id=finding.id, epss=None, epss_percentile=None, kev=False
        )
        breakdown = scoring.score(finding, enrichment, make_profile(), (), WEIGHTS)
        self.assertIsNone(breakdown.threat_multiplier)
        self.assertAlmostEqual(breakdown.risk, breakdown.env_score * 10, places=6)
        self.assertIn("no exploitation data", breakdown.reason)

    def test_low_confidence_inference_does_not_modify_the_vector(self):
        finding = make_finding()
        enrichment = make_enrichment(finding_id=finding.id)
        unsure = make_profile(
            role="database", role_confidence=0.3, exposure="internal", exposure_confidence=0.3
        )
        breakdown = scoring.score(finding, enrichment, unsure, (), WEIGHTS)
        self.assertNotIn("MAV", breakdown.env_modifications)
        self.assertEqual(breakdown.env_modifications.get("CR"), "M")

    def test_native_fallback_when_a_finding_has_no_cve(self):
        finding = make_finding(
            tool="zap",
            tool_native_id="10020",
            title="Missing Anti-clickjacking Header",
            cve_ids=[],
            native_severity="Medium",
            url="http://172.28.0.11/",
            evidence="x-frame-options",
            provenance=Provenance("zap", "tests/synthetic/x.json", 1, "unit"),
        )
        breakdown = scoring.score(finding, None, make_profile(), (), WEIGHTS)
        self.assertEqual(breakdown.risk, 40.0)
        self.assertEqual(breakdown.band, "Medium")
        self.assertEqual(breakdown.native_fallback, "zap:Medium=40")

    def test_missing_cvss_does_not_discard_observed_threat_facts(self) -> None:
        finding = make_finding(tool="zap", native_severity="Medium")
        enrichment = make_enrichment(finding_id=finding.id, cvss31_vector=None, cvss31_base=None)
        profile = make_profile(exposure="internet_facing")

        breakdown = scoring.score(finding, enrichment, profile, (), WEIGHTS)

        self.assertTrue(breakdown.kev)
        self.assertEqual(breakdown.epss_percentile, enrichment.epss_percentile)
        self.assertIsNone(breakdown.env_score)
        self.assertIsNone(breakdown.threat_multiplier)
        self.assertEqual(breakdown.native_fallback, "zap:Medium=40")
        self.assertGreaterEqual(breakdown.risk, WEIGHTS["threat"]["kev_floor_internet_facing"])
        self.assertIn("KEV", breakdown.reason)

    def test_severity_baselines_do_not_inherit_a_native_kev_floor(self) -> None:
        listed = make_finding(tool="zap", tool_native_id="synthetic-kev", native_severity="Low")
        unlisted = make_finding(
            tool="zap", tool_native_id="synthetic-unlisted", native_severity="High", cve_ids=[]
        )
        enrichment = make_enrichment(finding_id=listed.id, cvss31_vector=None, cvss31_base=None)
        profile = make_profile(exposure="internet_facing")
        with (
            TemporaryDirectory() as directory,
            Store(Path(directory) / "synthetic_baselines.db") as store,
        ):
            store.start_run("synthetic-baselines", SETTINGS.config_hash())
            store.upsert_findings("synthetic-baselines", [listed, unlisted])
            for finding, matched in ((listed, enrichment), (unlisted, None)):
                store.upsert_score(
                    "synthetic-baselines", scoring.score(finding, matched, profile, (), WEIGHTS)
                )
            orders = pipeline.baseline_orders(store, "synthetic-baselines")

        self.assertEqual(orders["ours"][0], listed.id)
        self.assertEqual(orders["cvss_only"][0], unlisted.id)
        self.assertEqual(orders["cvss_epss"][0], unlisted.id)

    def test_scoring_is_deterministic(self):
        finding = make_finding()
        enrichment = make_enrichment(finding_id=finding.id)
        profile = make_profile(role="database", exposure="internet_facing")
        first = scoring.score(finding, enrichment, profile, (), WEIGHTS)
        second = scoring.score(finding, enrichment, profile, (), WEIGHTS)
        self.assertEqual(
            json.dumps(first.to_json(), sort_keys=True),
            json.dumps(second.to_json(), sort_keys=True),
        )

    def test_stored_model_context_cannot_bypass_canonical_policy(self) -> None:
        finding = make_finding()
        enrichment = make_enrichment(finding_id=finding.id)
        for source in ("model", "llm"):
            with self.subTest(source=source):
                profile = make_profile()
                profile = replace(profile, role=replace(profile.role, source=source))
                with self.assertRaisesRegex(ConfigError, "context-source ADR"):
                    scoring.score(finding, enrichment, profile, (), WEIGHTS)

    def test_ranking_refuses_missing_host_context_without_dropping_findings(self) -> None:
        with (
            TemporaryDirectory() as directory,
            Store(Path(directory) / "synthetic_missing_context.db") as store,
        ):
            store.start_run("synthetic-context", SETTINGS.config_hash())
            store.upsert_profile("synthetic-context", make_profile(host_ip="172.28.0.10"))
            store.upsert_findings(
                "synthetic-context",
                [make_finding(host_ip="172.28.0.10"), make_finding(host_ip="172.28.0.12")],
            )
            with self.assertRaisesRegex(ConfigError, "172.28.0.12"):
                pipeline.do_rank(SETTINGS, store, "synthetic-context")
            self.assertEqual(store.scores("synthetic-context"), [])

    def test_scoring_module_is_pure(self):
        source = (ROOT / "vulnassess" / "scoring.py").read_text(encoding="utf-8")
        for forbidden in (
            "import socket",
            "import subprocess",
            "import requests",
            "import urllib",
            "import random",
            "import os",
            "open(",
            "datetime.now",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_fix_text_uses_the_version_bound_and_the_patch_reference(self):
        finding = make_finding()
        enrichment = make_enrichment(
            finding_id=finding.id,
            version_end="2.4.51",
            patch_references=("https://httpd.apache.org/security/vulnerabilities_24.html",),
        )
        services = (
            service(
                80,
                "http",
                "80/tcp http Apache httpd 2.4.49",
                product="Apache httpd",
                version="2.4.49",
            ),
        )
        text = scoring.fix_text(finding, enrichment, services)
        self.assertIn("Upgrade Apache httpd 2.4.49 to 2.4.51 or later", text)
        self.assertIn("httpd.apache.org", text)


# --------------------------------------------------------------------------- context (9)
class TestContext(unittest.TestCase):
    def test_database_role_quotes_the_banner_that_triggered_it(self):
        host = Host(
            ip="172.28.0.12",
            services=(
                service(3306, "mysql", "3306/tcp mysql MySQL 5.5.62"),
                service(80, "http", "80/tcp http Apache httpd 2.4.49"),
            ),
        )
        role = context.infer_role(host, ROLES)
        self.assertEqual(role.value, "database")
        self.assertGreaterEqual(role.confidence, 0.7)
        self.assertIn("3306/tcp mysql MySQL 5.5.62", role.evidence)

    def test_web_frontend_role_from_port_service_and_banner(self):
        host = Host(
            ip="172.28.0.10",
            services=(
                service(80, "http", "80/tcp http Apache httpd 2.4.49"),
                service(22, "ssh", "22/tcp ssh SyntheticSSH 4.7p1"),
            ),
        )
        role = context.infer_role(host, ROLES)
        self.assertEqual(role.value, "web_frontend")
        self.assertGreaterEqual(role.confidence, 0.7)

    def test_domain_controller_needs_both_kerberos_and_ldap(self):
        one = Host(ip="172.28.0.10", services=(service(88, "kerberos-sec", "88/tcp kerberos-sec"),))
        both = Host(
            ip="172.28.0.10",
            services=(
                service(88, "kerberos-sec", "88/tcp kerberos-sec"),
                service(389, "ldap", "389/tcp ldap"),
            ),
        )
        weak = context.infer_role(one, ROLES)
        strong = context.infer_role(both, ROLES)
        self.assertEqual(weak.confidence, 0.2, "the all_of port rule must not fire on one port")
        self.assertEqual(strong.value, "domain_controller")
        self.assertGreaterEqual(strong.confidence, 0.8)

    def test_workstation_role_from_the_operating_system(self):
        host = Host(ip="172.28.0.10", os_guess="Microsoft Windows 11 22H2", services=())
        self.assertEqual(context.infer_role(host, ROLES).value, "workstation")

    def test_embedded_banner_outranks_a_plain_web_server(self):
        host = Host(
            ip="172.28.0.10",
            services=(service(80, "http", "80/tcp http GoAhead-Webs embedded httpd"),),
        )
        role = context.infer_role(host, ROLES)
        self.assertEqual(role.value, "iot_embedded")
        self.assertIn("GoAhead", role.evidence)

    def test_unknown_role_when_no_rule_fires(self):
        role = context.infer_role(Host(ip="172.28.0.11", services=()), ROLES)
        self.assertEqual(role.value, "unknown")
        self.assertEqual(role.confidence, 0.2)
        self.assertEqual(role.evidence, "none observed")

    def test_exposure_uses_the_address_then_the_scope_tag(self):
        internal, segment = context.infer_exposure(Host(ip="172.28.0.10"), SETTINGS.scope)
        self.assertEqual(internal.value, "internal")
        self.assertEqual(segment, "172.28.0.10/32")
        self.assertIn("private", internal.evidence)

        tagged, _ = context.infer_exposure(Host(ip="172.28.0.12"), SETTINGS.scope)
        self.assertEqual(tagged.value, "internet_facing")
        self.assertIn("tags.vantage=external", tagged.evidence)

        routable, _ = context.infer_exposure(Host(ip="8.8.8.8"), SETTINGS.scope)
        self.assertEqual(routable.value, "internet_facing")
        self.assertIn("globally routable", routable.evidence)

    def test_waf_is_detected_and_unobserved_controls_remain_unknown(self):
        quiet = Host(ip="172.28.0.10", services=(service(80, "http", "80/tcp http nginx"),))
        controls = context.detect_controls(quiet, [], CONTROLS)
        self.assertEqual(sorted(controls), ["auth_required", "rate_limiting", "tls", "waf"])
        for key, feature in controls.items():
            with self.subTest(control=key):
                self.assertIsNone(feature.value)
                self.assertEqual(feature.confidence, 0.0)
                self.assertEqual(feature.evidence, "none observed")

        behind = Host(
            ip="172.28.0.10",
            services=(service(80, "http", "80/tcp http nginx cf-ray: 7a1b2c3d4e5f-LHR"),),
        )
        detected = context.detect_controls(behind, [], CONTROLS)
        self.assertEqual(detected["waf"].value, "Cloudflare")
        self.assertIn("cf-ray", detected["waf"].evidence)

    def test_every_feature_in_a_built_profile_carries_evidence(self):
        hosts, findings = parse_nmap_xml(NMAP_SYNTH, "unit")
        host = next(item for item in hosts if item.ip == "172.28.0.12")
        profile = context.build_profile(host, findings, SETTINGS.scope, ROLES, CONTROLS)
        features = [
            profile.role,
            profile.exposure,
            *profile.controls.values(),
            *profile.manual.values(),
        ]
        self.assertGreaterEqual(len(features), 6)
        for feature in features:
            self.assertTrue(feature.evidence.strip())
            self.assertIn(feature.source, ("rule", "manual"))


# --------------------------------------------------------------------------- readers, scope, import (8)
class TestReadersAndImport(unittest.TestCase):
    def test_synthetic_nmap_yields_two_live_hosts_and_two_findings(self):
        hosts, findings = parse_nmap_xml(NMAP_SYNTH, "unit")
        self.assertEqual([host.ip for host in hosts], ["172.28.0.10", "172.28.0.12"])
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(finding.cve_ids == ("CVE-1999-9001",) for finding in findings))
        self.assertTrue(all(finding.native_severity is None for finding in findings))
        exposed = next(host for host in hosts if host.ip == "172.28.0.12")
        self.assertEqual({item.port for item in exposed.services}, {80, 3306})

    def test_synthetic_zap_yields_four_distinct_findings(self):
        findings = parse_zap_json(ZAP_SYNTH, "unit")
        self.assertEqual(len(findings), 4)
        self.assertEqual(len({finding.id for finding in findings}), 4)
        clickjacking = [item for item in findings if item.tool_native_id == "10020"]
        self.assertEqual(len(clickjacking), 2)
        self.assertEqual(clickjacking[0].cwe_ids, ("CWE-1021",))
        self.assertEqual(
            {finding.native_severity for finding in findings}, {"Medium", "Informational"}
        )

    def test_unusable_scanner_files_raise_adapter_error_only(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            broken_xml = root / "broken.xml"
            broken_xml.write_text("<nmaprun><host>", encoding="utf-8")
            wrong_root = root / "wrong.xml"
            wrong_root.write_text("<report><host/></report>", encoding="utf-8")
            broken_json = root / "broken.json"
            broken_json.write_text("{not json", encoding="utf-8")

            for path in (broken_xml, wrong_root, root / "absent.xml"):
                with self.subTest(path=path.name):
                    with self.assertRaises(AdapterError):
                        parse_nmap_xml(path, "unit")
            with self.assertRaises(AdapterError):
                parse_zap_json(broken_json, "unit")

    def test_scope_refuses_an_unknown_key_a_stray_target_and_an_in_scope_canary(self):
        cases = {
            "unknown key": "allowed_cidrs: [172.28.0.10/32]\nallowed_ports: [22]\n",
            "outside": "allowed_cidrs: [172.28.0.10/32]\nlab_targets:\n  - {name: x, ip: 10.0.0.4}\n",
            "canary inside": "allowed_cidrs: [172.28.0.0/24]\ncanary: {ip: 172.28.0.250}\n",
        }
        with TemporaryDirectory() as directory:
            for label, text in cases.items():
                with self.subTest(case=label):
                    root = Path(directory) / label.replace(" ", "_")
                    root.mkdir()
                    (root / "scope.yaml").write_text(text, encoding="utf-8")
                    for name in ("weights.yaml", "roles.yaml", "controls.yaml"):
                        (root / name).write_text(
                            (ROOT / "config" / name).read_text(encoding="utf-8"), encoding="utf-8"
                        )
                    with self.assertRaises(ConfigError):
                        Settings(root)

    def test_an_out_of_scope_import_reads_nothing(self):
        with TemporaryDirectory() as directory:
            with temp_store(directory) as store:
                with self.assertRaises(ScopeError) as caught:
                    pipeline.do_import(
                        SETTINGS, store, "r1", "8.8.8.8", Path(directory) / "absent.xml"
                    )
            self.assertIn("nothing was read", str(caught.exception))
            self.assertFalse((Path(directory) / "data" / "raw").exists())

    def test_the_canary_is_refused_by_name(self):
        with TemporaryDirectory() as directory:
            with temp_store(directory) as store:
                with self.assertRaises(ScopeError) as caught:
                    pipeline.do_import(SETTINGS, store, "r1", "172.28.0.250", NMAP_SYNTH)
            self.assertIn("canary", str(caught.exception))
            self.assertIn("nothing was read", str(caught.exception))

    def test_import_stores_findings_with_a_raw_copy_and_provenance(self):
        with TemporaryDirectory() as directory:
            with temp_store(directory) as store:
                summary = pipeline.do_import(SETTINGS, store, "r1", "172.28.0.10", NMAP_SYNTH)
                self.assertEqual(summary["findings"]["nmap"], 1)
                findings = store.findings("r1")
            raw = Path(directory) / "data" / "raw" / "r1" / NMAP_SYNTH.name
            self.assertTrue(raw.is_file())
            self.assertEqual(len(findings), 1)
            self.assertTrue(findings[0].provenance.raw_path.endswith(NMAP_SYNTH.name))
            self.assertIn(str(Path("raw") / "r1"), findings[0].provenance.raw_path)

    def test_a_repeated_import_inserts_no_new_findings(self):
        with TemporaryDirectory() as directory:
            with temp_store(directory) as store:
                first = pipeline.do_import(SETTINGS, store, "r1", "172.28.0.12", NMAP_SYNTH)
                second = pipeline.do_import(SETTINGS, store, "r1", "172.28.0.12", NMAP_SYNTH)
                self.assertEqual(first["findings"]["nmap"], 1)
                self.assertEqual(second["findings"]["nmap"], 0)
                self.assertEqual(len(store.findings("r1")), 1)


# --------------------------------------------------------------------------- intel (3)
class TestIntel(unittest.TestCase):
    def test_an_empty_feed_directory_names_all_three_snapshots(self):
        with TemporaryDirectory() as directory:
            with temp_store(directory) as store:
                with self.assertRaises(IntelUnavailable) as caught:
                    intel.load_feeds(Path(directory) / "feeds", store)
            message = str(caught.exception)
            for expected in ("nvd", "epss", "kev.json"):
                self.assertIn(expected, message)

    def test_synthetic_feeds_load_and_attach_to_both_nmap_findings(self):
        with TemporaryDirectory() as directory:
            with temp_store(directory) as store:
                counts = intel.load_feeds(FEEDS_SYNTH, store)
                self.assertEqual(counts, {"nvd": 2, "epss": 2, "kev": 1})
                meta = store.feeds_meta()
                self.assertEqual(meta["epss"]["file_date"], "2026-09-05")
                for feed in ("nvd", "epss", "kev"):
                    self.assertEqual(len(meta[feed]["sha256"]), 64)

                pipeline.do_import(SETTINGS, store, "r1", "172.28.0.10", NMAP_SYNTH)
                pipeline.do_import(SETTINGS, store, "r1", "172.28.0.12", NMAP_SYNTH)
                result = intel.enrich_run("r1", store)
                self.assertEqual(result["matched"], 2)

                for finding in store.findings("r1"):
                    enrichments = store.enrichments(finding.id)
                    self.assertEqual([item.cve_id for item in enrichments], ["CVE-1999-9001"])
                    enrichment = enrichments[0]
                    self.assertTrue(enrichment.kev)
                    self.assertAlmostEqual(enrichment.epss_percentile, 0.9987)
                    self.assertEqual(enrichment.cvss31_base, 9.8)
                    self.assertTrue(
                        any("httpd.apache.org" in url for url in enrichment.patch_references)
                    )

    def test_cpe_version_range_boundaries(self):
        cpe_match = {
            "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "2.4.49",
            "versionEndExcluding": "2.4.51",
        }
        for version, expected in (
            ("2.4.49", True),
            ("2.4.50", True),
            ("2.4.51", False),
            ("2.4.48", False),
        ):
            with self.subTest(version=version):
                matched, _, _ = intel._in_range(version, cpe_match)
                self.assertEqual(matched, expected)
        matched, confidence, end = intel._in_range("unknown-build", cpe_match)
        self.assertTrue(matched)
        self.assertEqual(confidence, 0.5)
        self.assertEqual(end, "2.4.51")


# --------------------------------------------------------------------------- evaluation (6)
class TestEvaluate(unittest.TestCase):
    EXPERT = ["A", "B", "C", "D"]

    def test_tau_b_hand_case_and_full_reversal(self):
        expert = evaluate.positions(self.EXPERT)
        ours = evaluate.positions(["A", "C", "B", "D"])
        self.assertEqual(evaluate.kendall_tau_b(ours, expert), 0.6667)
        reversed_order = evaluate.positions(["D", "C", "B", "A"])
        self.assertEqual(evaluate.kendall_tau_b(reversed_order, expert), -1.0)

    def test_tau_b_tolerates_a_tie(self):
        expert = evaluate.positions(self.EXPERT)
        tied = evaluate.positions(["A", ["B", "C"], "D"])
        self.assertGreater(evaluate.kendall_tau_b(tied, expert), 0.9)

    def test_critical_queue_hand_cases(self):
        self.assertEqual(
            evaluate.critical_queue_at_full_recall(["A", "C", "B", "D"], {"A", "C"}), 2
        )
        self.assertEqual(
            evaluate.critical_queue_at_full_recall(["B", "A", "D", "C"], {"A", "C"}), 4
        )

    def test_ndcg_is_one_for_perfect_agreement_and_lower_when_reversed(self):
        self.assertEqual(evaluate.ndcg_at_k(self.EXPERT, self.EXPERT, 10), 1.0)
        self.assertLess(evaluate.ndcg_at_k(["D", "C", "B", "A"], self.EXPERT, 10), 1.0)

    def test_kendall_w_is_one_for_identical_raters_and_zero_when_opposed(self):
        self.assertEqual(evaluate.kendall_w([self.EXPERT, list(self.EXPERT)]), 1.0)
        self.assertLess(evaluate.kendall_w([self.EXPERT, ["D", "C", "B", "A"]]), 0.1)

    def test_a_single_expert_reports_the_limitation(self):
        truth = {"experts": [{"name": "one", "ranking": self.EXPERT}], "expert_critical": ["A"]}
        result = evaluate.evaluate({"ours": self.EXPERT}, truth)
        self.assertIsNone(result["kendall_w"])
        self.assertIn("single-annotator", result["limitation"])


# --------------------------------------------------------------------------- end to end (2)
class TestEndToEnd(unittest.TestCase):
    def test_demo_produces_the_two_machine_contrast_and_a_self_contained_report(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / "report.html"
            argv = [
                "--config",
                str(ROOT / "config"),
                "--db",
                str(root / "data" / "vulnassess.db"),
                "demo",
                "--target",
                f"172.28.0.10:{NMAP_SYNTH}",
                "--target",
                f"172.28.0.12:{NMAP_SYNTH}",
                "--target",
                f"172.28.0.11:{NMAP_SYNTH}:{ZAP_SYNTH}",
                "--feeds",
                str(FEEDS_SYNTH),
                "--out",
                str(out),
            ]
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main(argv)
            output = buffer.getvalue()

            self.assertEqual(code, 0)
            self.assertIn("two-machine comparison", output)
            self.assertIn("Critical", output)
            self.assertTrue(out.is_file())

            html = out.read_text(encoding="utf-8")
            for heading in (
                "1. Summary",
                "2. Ranked findings",
                "3. Host context and evidence",
                "4. Methodology",
                "5. Provenance",
            ):
                self.assertIn(heading, html)
            self.assertNotIn("<script", html)
            self.assertNotIn("href=", html)
            self.assertNotIn("src=", html)

            with Store(root / "data" / "vulnassess.db") as store:
                scores = {item.host_ip: item for item in store.scores("demo")}
                self.assertEqual(scores["172.28.0.12"].band, "Critical")
                self.assertNotEqual(scores["172.28.0.10"].band, "Critical")
                self.assertLess(scores["172.28.0.10"].risk, scores["172.28.0.12"].risk)
                for item in store.scores("demo"):
                    self.assertIn(str(item.risk), html)

                orders = pipeline.baseline_orders(store, "demo")
                truth_path = root / "synthetic_groundtruth.yaml"
                truth_path.write_text(
                    yaml.safe_dump(build_synthetic_truth(orders["ours"]), sort_keys=False),
                    encoding="utf-8",
                )
                result = pipeline.do_eval(store, "demo", truth_path)

            self.assertEqual(len(result["experts"]), 2)
            self.assertIsNotNone(result["kendall_w"])
            self.assertGreaterEqual(
                result["methods"]["ours"]["tau_b_mean"],
                result["methods"]["cvss_only"]["tau_b_mean"],
            )

    def test_cli_exit_codes(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = str(root / "data" / "vulnassess.db")
            errors = io.StringIO()
            with redirect_stderr(errors), redirect_stdout(io.StringIO()):
                scope_code = main(
                    [
                        "--config",
                        str(ROOT / "config"),
                        "--db",
                        database,
                        "import",
                        "--run-id",
                        "r1",
                        "--target-ip",
                        "8.8.8.8",
                        "--nmap",
                        str(root / "absent.xml"),
                    ]
                )
                intel_code = main(
                    ["--db", database, "intel", "load", "--from-dir", str(root / "no-feeds")]
                )
            self.assertEqual(scope_code, 3)
            self.assertEqual(intel_code, 5)
            self.assertIn("ScopeError", errors.getvalue())
            self.assertIn("IntelUnavailable", errors.getvalue())


def build_synthetic_truth(order: list[str]) -> dict:
    """SYNTHETIC expert rankings derived from real finding ids. Not human judgment."""
    agreeing = list(order)
    swapped = list(order)
    if len(swapped) >= 3:
        swapped[1], swapped[2] = swapped[2], swapped[1]
    tied: list = list(swapped)
    if len(tied) >= 5:
        tied = tied[:3] + [[tied[3], tied[4]]] + tied[5:]
    return {
        "_comment": "SYNTHETIC expert rankings for tests; not real expert judgment.",
        "experts": [
            {"name": "synthetic-expert-a", "ranking": agreeing},
            {"name": "synthetic-expert-b", "ranking": tied},
        ],
        "expert_critical": order[:2],
    }


# --------------------------------------------------------------------------- nikto reader
class TestNiktoReader(unittest.TestCase):
    def test_synthetic_nikto_yields_findings_without_inventing_severity(self):
        findings = parse_nikto_json(NIKTO_SYNTH, "unit")
        self.assertEqual(len(findings), 3)
        self.assertEqual(len({finding.id for finding in findings}), 3)
        self.assertTrue(all(finding.tool == "nikto" for finding in findings))
        self.assertTrue(all(finding.native_severity is None for finding in findings))
        self.assertTrue(all(finding.evidence.strip() for finding in findings))

    def test_nikto_extracts_a_cve_from_the_message_and_references(self):
        findings = parse_nikto_json(NIKTO_SYNTH, "unit")
        with_cve = [finding for finding in findings if finding.cve_ids]
        self.assertEqual(len(with_cve), 1)
        self.assertEqual(with_cve[0].cve_ids, ("CVE-1999-9001",))
        self.assertTrue(any("httpd.apache.org" in url for url in with_cve[0].reference_urls))

    def test_unusable_nikto_files_raise_adapter_error_only(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "broken.json").write_text("{not json", encoding="utf-8")
            (root / "wrong.json").write_text('{"host": "x"}', encoding="utf-8")
            for name in ("broken.json", "wrong.json", "absent.json"):
                with self.subTest(name=name):
                    with self.assertRaises(AdapterError):
                        parse_nikto_json(root / name, "unit")

    def test_nikto_findings_rank_on_the_scalar_fallback(self):
        finding = parse_nikto_json(NIKTO_SYNTH, "unit")[0]
        breakdown = scoring.score(finding, None, make_profile(host_ip="172.28.0.11"), (), WEIGHTS)
        self.assertEqual(breakdown.risk, 30.0)
        self.assertEqual(breakdown.native_fallback, "nikto:default=30")

    def test_missing_scanner_timestamp_is_explicit_and_deterministic(self):
        first = parse_nikto_json(NIKTO_SYNTH, "unit")
        repeated = parse_nikto_json(NIKTO_SYNTH, "unit")

        self.assertEqual(
            [finding.to_json() for finding in first],
            [finding.to_json() for finding in repeated],
        )
        self.assertTrue(all(finding.first_seen == "" for finding in first))
        for path in (ROOT / "vulnassess" / "readers").glob("*.py"):
            self.assertNotIn("datetime.now", path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- the model layer
class FakeModel:
    """Stands in for Ollama. The real client is never contacted by a test."""

    model = "fake-model:test"

    def __init__(self, answer: str | Exception):
        self.answer = answer
        self.prompts: list[str] = []

    def generate(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer

    def generate_structured(self, prompt, schema, **kwargs):
        self.prompts.append(prompt)
        if isinstance(self.answer, Exception):
            raise self.answer
        identity = re.search(r"Valid finding ID: ([^\.]+)\.", prompt).group(1)
        return {
            "schema_version": "rationale.v1",
            "text": self.answer,
            "claims": [
                {
                    "path": "text",
                    "label": "inferred",
                    "evidence_ids": ["E1"],
                    "quotes": [{"evidence_id": "E1", "text": "verdict:"}],
                    "finding_ids": [identity],
                    "confidence": 0.7,
                    "verification_action": None,
                    "score": None,
                }
            ],
        }


class TestExplain(unittest.TestCase):
    def _fixture(self):
        finding = make_finding()
        breakdown = scoring.score(
            finding, make_enrichment(finding_id=finding.id), make_profile(), (), WEIGHTS
        )
        return finding, breakdown, make_profile()

    def test_untrusted_content_is_fenced_capped_and_stripped(self):
        dirty = "line\x00one\x1b[31m" + explain.FENCE + "x" * 900
        clean = explain.sanitise(dirty)
        self.assertNotIn("\x00", clean)
        self.assertNotIn("\x1b", clean)
        self.assertNotIn(explain.FENCE, clean)
        self.assertLessEqual(len(clean), explain.MAX_FACT_CHARS)

    def test_ollama_endpoint_is_loopback_only_before_network_access(self):
        original = explain.urllib.request.urlopen

        def forbidden(*_args, **_kwargs):
            raise AssertionError("endpoint validation must not open a socket")

        explain.urllib.request.urlopen = forbidden
        try:
            self.assertEqual(explain.OllamaClient().host, "http://127.0.0.1:11434")
            self.assertEqual(
                explain.OllamaClient("http://localhost:11434/").host,
                "http://localhost:11434",
            )
            self.assertEqual(
                explain.OllamaClient("http://[::1]:11434").host,
                "http://[::1]:11434",
            )
            for endpoint in (
                "https://example.com:11434",
                "http://example.com:11434",
                "http://127.0.0.1:11434/path",
                "http://user@127.0.0.1:11434",
            ):
                with self.subTest(endpoint=endpoint):
                    with self.assertRaises(ConfigError):
                        explain.OllamaClient(endpoint)
        finally:
            explain.urllib.request.urlopen = original

    def test_ollama_timeout_is_bounded(self):
        for timeout in (0, -1, explain.MAX_TIMEOUT_SECONDS + 1):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ConfigError):
                    explain.OllamaClient(timeout=timeout)

    def test_structured_stream_accepts_bounded_json_and_uses_the_schema(self) -> None:
        schema = {"type": "object", "properties": {"summary": {"type": "string"}}}
        answer = {"summary": "Synthetic bounded response"}
        content = json.dumps(answer)
        body = b"".join(
            (json.dumps({"message": {"content": chunk}, "done": done}) + "\n").encode("utf-8")
            for chunk, done in ((content[:10], False), (content[10:], True))
        )
        with patch.object(
            explain.urllib.request, "urlopen", return_value=io.BytesIO(body)
        ) as transport:
            result = explain.OllamaClient().generate_structured("synthetic prompt", schema)
        self.assertEqual(result, answer)
        self.assertEqual(json.loads(transport.call_args.args[0].data)["format"], schema)

    def test_structured_stream_reports_received_bytes_without_exposing_content(self) -> None:
        answer = {"summary": "x" * 700}
        body = (
            json.dumps({"message": {"content": json.dumps(answer)}, "done": True}) + "\n"
        ).encode("utf-8")
        reports = []
        with patch.object(explain.urllib.request, "urlopen", return_value=io.BytesIO(body)):
            result = explain.OllamaClient().generate_structured(
                "synthetic prompt", {}, on_progress=reports.append
            )
        self.assertEqual(result, answer)
        self.assertEqual(reports, [len(json.dumps(answer).encode("utf-8"))])

    def test_structured_stream_rejects_oversized_content(self) -> None:
        content = json.dumps({"summary": "x" * 600})
        chunks = [content[index : index + 32] for index in range(0, len(content), 32)]
        body = b"".join(
            (
                json.dumps({"message": {"content": chunk}, "done": index == len(chunks) - 1}) + "\n"
            ).encode("utf-8")
            for index, chunk in enumerate(chunks)
        )
        with (
            patch.object(explain, "MAX_RESPONSE_BYTES", 128),
            patch.object(explain.urllib.request, "urlopen", return_value=io.BytesIO(body)),
            self.assertRaisesRegex(LLMUnavailable, "exceeds"),
        ):
            explain.OllamaClient().generate_structured("synthetic prompt", {})

    def test_structured_stream_requires_explicit_completion(self) -> None:
        event = {"message": {"content": '{"summary":"partial"}'}, "done": False}
        body = (json.dumps(event) + "\n").encode("utf-8")
        with (
            patch.object(explain.urllib.request, "urlopen", return_value=io.BytesIO(body)),
            self.assertRaisesRegex(LLMUnavailable, "completion"),
        ):
            explain.OllamaClient().generate_structured("synthetic prompt", {})

    def test_structured_stream_rejects_malformed_events(self) -> None:
        for event in ([], {"message": []}, {"message": {"content": {}}}):
            with self.subTest(event=event):
                body = (json.dumps(event) + "\n").encode("utf-8")
                with (
                    patch.object(explain.urllib.request, "urlopen", return_value=io.BytesIO(body)),
                    self.assertRaises(LLMUnavailable),
                ):
                    explain.OllamaClient().generate_structured("synthetic prompt", {})

    def test_the_prompt_labels_the_data_untrusted_and_hides_every_score(self):
        finding, breakdown, profile = self._fixture()
        facts = explain.facts_for(breakdown, profile, finding)
        prompt = explain.build_prompt(facts)
        self.assertIn(explain.UNTRUSTED_PREFIX, prompt)
        self.assertEqual(prompt.count(explain.FENCE), 2)
        self.assertIn("internal", prompt)
        for secret in (str(breakdown.risk), str(breakdown.base_score), str(breakdown.env_score)):
            self.assertNotIn(secret, prompt)

    def test_a_model_may_not_invent_a_number(self):
        facts = {"verdict": "High", "exposure": "internal"}
        accepted, record = explain.validate(
            "High risk: this internal host scores 9.8 out of 10.", facts
        )
        self.assertFalse(accepted)
        self.assertTrue(any("invented number" in problem for problem in record["problems"]))

    def test_malformed_model_output_is_rejected(self):
        facts = {"verdict": "High", "exposure": "internal"}
        cases = {
            "empty": "",
            "two lines": "First line.\nSecond line.",
            "markdown": "```High risk.```",
            "url": "See http://example.invalid for details.",
            "too long": "High. " * 80,
        }
        for label, answer in cases.items():
            with self.subTest(case=label):
                accepted, _ = explain.validate(answer, facts)
                self.assertFalse(accepted)
        accepted, record = explain.validate(
            "An internal web frontend in a test environment is actively exploited.", facts
        )
        self.assertTrue(accepted, record)

    def test_an_unavailable_model_falls_back_to_the_deterministic_sentence(self):
        finding, breakdown, profile = self._fixture()
        client = FakeModel(LLMUnavailable("MISSING model; a human must run: ollama pull x"))
        rationale = explain.rationale_for(breakdown, profile, finding, client)
        self.assertEqual(rationale.source, "template")
        self.assertEqual(rationale.text, breakdown.reason)
        self.assertFalse(rationale.validation["accepted"])

    def test_a_rejected_sentence_falls_back_and_records_why(self):
        finding, breakdown, profile = self._fixture()
        client = FakeModel("Risk is 42 out of 100 for this host.")
        rationale = explain.rationale_for(breakdown, profile, finding, client)
        self.assertEqual(rationale.source, "template")
        self.assertEqual(rationale.text, breakdown.reason)
        self.assertTrue(any("invented number" in p for p in rationale.validation["problems"]))

    def test_a_valid_sentence_is_accepted_and_attributed(self):
        finding, breakdown, profile = self._fixture()
        good = "This internal web frontend is being actively exploited and has no protection."
        rationale = explain.rationale_for(breakdown, profile, finding, FakeModel(good))
        self.assertEqual(rationale.source, "llm")
        self.assertEqual(rationale.text, good)
        self.assertEqual(rationale.model, "fake-model:test")

    def test_explaining_a_run_never_changes_a_score(self):
        with TemporaryDirectory() as directory:
            with temp_store(directory) as store:
                intel.load_feeds(FEEDS_SYNTH, store)
                pipeline.do_import(SETTINGS, store, "r1", "172.28.0.12", NMAP_SYNTH)
                intel.enrich_run("r1", store)
                pipeline.do_context(SETTINGS, store, "r1")
                before = [item.to_json() for item in pipeline.do_rank(SETTINGS, store, "r1")]

                good = "This internet-facing database is being actively exploited right now."
                counts = explain.explain_run("r1", store, FakeModel(good))
                after = [item.to_json() for item in store.scores("r1")]

                self.assertEqual(counts["llm"], len(before))
                self.assertEqual(counts["template"], 0)
                self.assertEqual(
                    json.dumps(before, sort_keys=True), json.dumps(after, sort_keys=True)
                )
                stored = store.rationales("r1")
                self.assertEqual(len(stored), len(before))
                self.assertTrue(all(item.text == good for item in stored.values()))


# --------------------------------------------------------------------------- scan orchestration
class TestRunner(unittest.TestCase):
    def test_planning_refuses_an_out_of_scope_target_and_the_canary(self):
        for target in ("8.8.8.8", "172.28.0.250", "192.168.0.116"):
            with self.subTest(target=target):
                with self.assertRaises(ScopeError) as caught:
                    runner.plan(SETTINGS, target, ["nmap"], "data/captures")
                self.assertIn("no command was built", str(caught.exception))

    def test_import_refuses_an_unlisted_target_before_creating_a_run(self) -> None:
        with (
            TemporaryDirectory() as directory,
            Store(Path(directory) / "synthetic_scope.db") as store,
        ):
            with self.assertRaises(ScopeError):
                pipeline.do_import(
                    SETTINGS, store, "synthetic-unlisted", "192.168.0.116", NMAP_SYNTH
                )
            self.assertIsNone(store.run_info("synthetic-unlisted"))

    def test_planning_builds_fixed_argument_lists_and_writes_nothing(self):
        with TemporaryDirectory() as directory:
            out = Path(directory) / "captures"
            commands = runner.plan(SETTINGS, "172.28.0.11", ["nmap", "nikto", "zap"], out)
            self.assertEqual([command.tool for command in commands], ["nmap", "nikto", "zap"])
            self.assertEqual(commands[0].argv[0], "nmap")
            self.assertIn("172.28.0.11", commands[0].argv)
            self.assertFalse(out.exists())
            for command in commands:
                self.assertIn(runner.NOT_RUN, command.notice)

    def test_planning_alone_never_starts_a_subprocess(self):
        def forbidden(*_args, **_kwargs):
            raise AssertionError("run_scan must not execute anything without execute=True")

        original = runner.subprocess.run
        runner.subprocess.run = forbidden
        try:
            with TemporaryDirectory() as directory:
                summary = runner.run_scan(SETTINGS, "172.28.0.11", ["nmap"], directory)
        finally:
            runner.subprocess.run = original
        self.assertFalse(summary["executed"])
        self.assertIn(runner.NOT_RUN, summary["commands"][0])

    def test_an_unknown_scanner_is_refused(self):
        with self.assertRaises(ConfigError):
            runner.plan(SETTINGS, "172.28.0.11", ["metasploit"], "data/captures")


# --------------------------------------------------------------------------- re-scan diff
class TestDiff(unittest.TestCase):
    def test_two_runs_are_compared_by_fingerprint(self):
        with TemporaryDirectory() as directory:
            with temp_store(directory) as store:
                pipeline.do_import(SETTINGS, store, "before", "172.28.0.10", NMAP_SYNTH)
                pipeline.do_import(SETTINGS, store, "before", "172.28.0.11", NMAP_SYNTH, ZAP_SYNTH)
                pipeline.do_import(SETTINGS, store, "after", "172.28.0.10", NMAP_SYNTH)

                result = diff.diff_runs(store, "before", "after")
                self.assertEqual(result["counts"]["resolved"], 4)
                self.assertEqual(result["counts"]["absent"], 4)
                self.assertEqual(result["counts"]["new"], 0)
                self.assertEqual(result["counts"]["persisting"], 1)
                rendered = diff.markdown_table(result).lower()
                self.assertIn("absent", rendered)
                self.assertIn("not observed", rendered)
                self.assertNotIn(" resolved", rendered)

    def test_a_missing_run_is_named(self):
        with TemporaryDirectory() as directory:
            with temp_store(directory) as store:
                pipeline.do_import(SETTINGS, store, "before", "172.28.0.10", NMAP_SYNTH)
                with self.assertRaises(ConfigError) as caught:
                    diff.diff_runs(store, "before", "never-ran")
        self.assertIn("never-ran", str(caught.exception))


# --------------------------------------------------------------------------- architectural walls
class TestWalls(unittest.TestCase):
    NETWORK = ("urllib.request", "urllib.error", "import httpx", "import requests", "import socket")

    def test_only_the_model_layer_imports_a_network_client(self):
        """Network I/O stays in explicit transports and the scoped DNS preflight."""
        permitted = {
            "explain.py": {"urllib.request", "urllib.error"},
            "openrouter.py": {"urllib.request", "urllib.error"},
            "groq.py": {"urllib.request", "urllib.error"},
            "target_intake.py": {"import socket"},
        }
        for path in sorted((ROOT / "vulnassess").rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            for token in self.NETWORK:
                with self.subTest(module=path.name, token=token):
                    if token in permitted.get(path.name, set()):
                        continue
                    self.assertNotIn(token, source)

    def test_scoring_imports_no_adapter_feed_or_model_code(self):
        source = (ROOT / "vulnassess" / "scoring.py").read_text(encoding="utf-8")
        for token in ("import explain", "import intel", "import readers", "import report"):
            with self.subTest(token=token):
                self.assertNotIn(token, source)


# --------------------------------------------------------------------------- real fixtures (2)
def real_fixture_paths(directory: Path, pattern: str) -> list[Path]:
    return sorted(
        path
        for path in directory.glob(pattern)
        if not path.name.lower().startswith(("example-", "synthetic_", "synthetic-"))
    )


class TestRealFixtures(unittest.TestCase):
    def test_example_and_synthetic_names_never_count_as_real(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for name in (
                "EXAMPLE-synthetic-capture.xml",
                "synthetic_capture.xml",
                "synthetic-capture.xml",
            ):
                (root / name).write_text("synthetic", encoding="utf-8")

            self.assertEqual(real_fixture_paths(root, "*.xml"), [])

    def test_real_nmap_captures_parse(self):
        captures = real_fixture_paths(FIXTURES / "nmap", "*.xml")
        if not captures:
            self.skipTest("fixture not provided: tests/fixtures/nmap/*.xml")
        for path in captures:
            with self.subTest(capture=path.name):
                hosts, _ = parse_nmap_xml(path, "fixture")
                self.assertGreaterEqual(len(hosts), 1)

    def test_real_zap_reports_parse(self):
        reports = real_fixture_paths(FIXTURES / "zap", "*.json")
        if not reports:
            self.skipTest("fixture not provided: tests/fixtures/zap/*.json")
        for path in reports:
            with self.subTest(report=path.name):
                self.assertGreaterEqual(len(parse_zap_json(path, "fixture")), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
