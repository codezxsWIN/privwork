"""A completed Nessus export reaches normalization, context, and scoring."""

import io
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from vulnassess import intel
from vulnassess.errors import AdapterError
from vulnassess.settings import Settings
from vulnassess.store import Store
from vulnassess.ui.server import UiApplication, UiRequestHandler

ROOT = Path(__file__).resolve().parents[1]


class TestNessusWorkflow(unittest.TestCase):
    def test_local_upload_route_requires_explicit_action_and_imports(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "assessment.db"
            settings = Settings(ROOT / "config")
            with Store(database) as store:
                store.start_run("nessus-example", settings.config_hash())
            app = UiApplication(database, ROOT / "config", "nessus-example")
            report = (
                '<NessusClientData_v2><Report name="lab"><ReportHost name="172.28.0.12">'
                '<ReportItem severity="3" pluginID="123" pluginName="Network weakness" '
                'port="22" protocol="tcp"><plugin_output>Observed exposure</plugin_output>'
                "</ReportItem></ReportHost></Report></NessusClientData_v2>"
            ).encode()

            class MemoryConnection:
                def __init__(self, request: bytes):
                    self.input = io.BytesIO(request)
                    self.output = bytearray()

                def makefile(self, *_args):
                    return self.input

                def sendall(self, data):
                    self.output.extend(data)

                def settimeout(self, timeout):
                    self.timeout = timeout

            headers = (
                "POST /api/nessus-import HTTP/1.1\r\nHost: 127.0.0.1:8765\r\n"
                "Origin: http://127.0.0.1:8765\r\nX-VulnAssess-Action: nessus-import\r\n"
                "X-VulnAssess-Run: nessus-example\r\nX-VulnAssess-Target: 172.28.0.12\r\n"
                f"Content-Type: application/xml\r\nContent-Length: {len(report)}\r\n\r\n"
            ).encode()
            connection = MemoryConnection(headers + report)
            server = SimpleNamespace(application=app, server_address=("127.0.0.1", 8765))
            UiRequestHandler(connection, ("127.0.0.1", 1), server)
            self.assertIn(b"HTTP/1.0 200 OK", connection.output)
            with Store(database) as store:
                self.assertEqual(len(store.scores("nessus-example")), 1)

    def test_import_updates_existing_assessment_and_rejects_other_host(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "assessment.db"
            settings = Settings(ROOT / "config")
            with Store(database) as store:
                store.start_run("nessus-example", settings.config_hash())
            app = UiApplication(database, ROOT / "config", "nessus-example")
            report = (
                '<NessusClientData_v2><Report name="lab"><ReportHost name="172.28.0.12">'
                '<ReportItem severity="3" pluginID="123" pluginName="Network weakness" '
                'port="22" protocol="tcp"><plugin_output>Observed exposure</plugin_output>'
                "</ReportItem></ReportHost></Report></NessusClientData_v2>"
            ).encode()
            result = app.import_nessus_report("nessus-example", "172.28.0.12", report)
            self.assertEqual(result["import"]["findings"]["nessus"], 1)
            self.assertEqual(result["scores"], 1)
            with Store(database) as store:
                self.assertEqual(store.findings("nessus-example")[0].tool, "nessus")
                self.assertEqual(len(store.profiles("nessus-example")), 1)
                self.assertEqual(len(store.scores("nessus-example")), 1)
                self.assertEqual(
                    store.run_info("nessus-example")["summary"]["imports"][-1]["findings"][
                        "nessus"
                    ],
                    1,
                )
            with self.assertRaises(AdapterError):
                app.import_nessus_report("nessus-example", "172.28.0.10", report)

    def test_report_can_create_a_separate_assessment(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "assessment.db"
            with Store(database):
                pass
            app = UiApplication(database, ROOT / "config")
            report = (
                '<NessusClientData_v2><Report name="lab"><ReportHost name="172.28.0.12">'
                '<ReportItem severity="2" pluginID="456" pluginName="Second weakness" '
                'port="80" protocol="tcp"><description>Observed weakness</description>'
                "</ReportItem></ReportHost></Report></NessusClientData_v2>"
            ).encode()
            result = app.import_nessus_report("nessus-new", "172.28.0.12", report, new_run=True)
            self.assertEqual(result["run_id"], "nessus-new")
            with Store(database) as store:
                self.assertEqual(len(store.findings("nessus-new")), 1)
                self.assertEqual(len(store.scores("nessus-new")), 1)
            with self.assertRaises(AdapterError):
                app.import_nessus_report("nessus-rejected", "172.28.0.10", report, new_run=True)
            with Store(database) as store:
                self.assertIsNone(store.run_info("nessus-rejected"))

    def test_imported_cve_joins_local_nvd_epss_and_kev_snapshots(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "assessment.db"
            with Store(database) as store:
                intel.load_feeds(ROOT / "tests" / "synthetic" / "feeds", store)
            app = UiApplication(database, ROOT / "config")
            report = (
                '<NessusClientData_v2><Report name="lab"><ReportHost name="172.28.0.12">'
                '<ReportItem severity="3" pluginID="789" pluginName="Known weakness" '
                'port="80" protocol="tcp"><cve>CVE-1999-9001</cve>'
                "<plugin_output>Observed service</plugin_output></ReportItem>"
                "</ReportHost></Report></NessusClientData_v2>"
            ).encode()
            app.import_nessus_report("nessus-intel", "172.28.0.12", report, new_run=True)
            with Store(database) as store:
                finding = store.findings("nessus-intel")[0]
                enrichment = store.enrichments(finding.id)[0]
                score = store.scores("nessus-intel")[0]
            self.assertEqual(enrichment.cve_id, "CVE-1999-9001")
            self.assertIsNotNone(enrichment.epss_percentile)
            self.assertTrue(enrichment.kev)
            self.assertTrue(score.kev)


if __name__ == "__main__":
    unittest.main()
