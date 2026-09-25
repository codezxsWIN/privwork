"""Nessus exports must become target-bound, provenance-bearing findings."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from vulnassess.errors import AdapterError
from vulnassess.readers.nessus_xml import parse_nessus_xml


class TestNessusReader(unittest.TestCase):
    def test_imports_one_vulnerability_and_skips_inventory_items(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "scan.nessus"
            path.write_text(
                '<NessusClientData_v2><Report name="lab"><ReportHost name="lab-host">'
                '<HostProperties><tag name="host-ip">172.28.0.12</tag></HostProperties>'
                '<ReportItem port="443" protocol="tcp" severity="3" pluginID="123" '
                'pluginName="TLS issue"><description>Check TLS</description>'
                "<plugin_output>Observed setting</plugin_output><cve>CVE-2024-12345</cve>"
                '</ReportItem><ReportItem port="0" severity="0" pluginID="19506" '
                'pluginName="Scan information"/></ReportHost></Report></NessusClientData_v2>',
                encoding="utf-8",
            )
            findings = parse_nessus_xml(path, "lab-run", host_ip="172.28.0.12")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].tool, "nessus")
        self.assertEqual(findings[0].native_severity, "High")
        self.assertEqual(findings[0].cve_ids, ("CVE-2024-12345",))
        self.assertIn("Observed setting", findings[0].evidence)
        self.assertEqual(findings[0].provenance.run_id, "lab-run")

    def test_rejects_other_host_even_when_a_matching_host_exists(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "mixed.nessus"
            path.write_text(
                '<NessusClientData_v2><Report name="mixed">'
                '<ReportHost name="172.28.0.12"><ReportItem severity="3" pluginID="1" '
                'pluginName="First"/></ReportHost>'
                '<ReportHost name="172.28.0.13"><ReportItem severity="3" pluginID="2" '
                'pluginName="Second"/></ReportHost></Report></NessusClientData_v2>',
                encoding="utf-8",
            )
            with self.assertRaises(AdapterError):
                parse_nessus_xml(path, "lab-run", host_ip="172.28.0.12")

    def test_rejects_non_nessus_xml_and_entities(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "bad.nessus"
            path.write_text("<report><results/></report>", encoding="utf-8")
            with self.assertRaises(AdapterError):
                parse_nessus_xml(path, "lab-run", host_ip="172.28.0.12")
            path.write_text(
                '<!DOCTYPE NessusClientData_v2 [<!ENTITY x "bad">]>'
                "<NessusClientData_v2>&x;</NessusClientData_v2>",
                encoding="utf-8",
            )
            with self.assertRaises(AdapterError):
                parse_nessus_xml(path, "lab-run", host_ip="172.28.0.12")


if __name__ == "__main__":
    unittest.main()
