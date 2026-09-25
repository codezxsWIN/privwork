"""Completed Tenable .nessus XML export -> canonical vulnerability findings."""

import ipaddress
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from vulnassess.errors import AdapterError
from vulnassess.readers._input import read_capture, reject_xml_declarations, validate_tree
from vulnassess.schema import Finding, Provenance

SEVERITY = {"1": "Low", "2": "Medium", "3": "High", "4": "Critical"}
CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _address(host: ET.Element) -> str | None:
    for tag in host.findall("./HostProperties/tag"):
        if tag.get("name") == "host-ip" and tag.text and tag.text.strip():
            try:
                return str(ipaddress.ip_address(tag.text.strip()))
            except ValueError:
                return None
    name = (host.get("name") or "").strip()
    try:
        return str(ipaddress.ip_address(name))
    except ValueError:
        return None


def parse_nessus_xml(path: str | Path, run_id: str, host_ip: str | None = None) -> list[Finding]:
    """Require a recognizable export and a proven target IP before accepting records."""
    path, content = read_capture(path, "nessus")
    reject_xml_declarations(content, path, "nessus")
    try:
        root = ET.fromstring(content)
    except (ET.ParseError, ValueError) as error:
        raise AdapterError(f"nessus: {path} is not valid report XML ({error})") from error
    validate_tree(root, path, "nessus")
    if root.tag != "NessusClientData_v2" or root.find("Report") is None:
        raise AdapterError(f"nessus: {path} is not a .nessus XML scan export")
    if not root.findall("./Report/ReportHost"):
        raise AdapterError(
            f"nessus: {path} has no ReportHost; target coverage cannot be established"
        )

    findings: list[Finding] = []
    index = 0
    for host in root.findall("./Report/ReportHost"):
        address = _address(host)
        if not address:
            raise AdapterError(f"nessus: {path} has a ReportHost without a verified host-ip")
        if host_ip and address != str(ipaddress.ip_address(host_ip)):
            raise AdapterError(
                f"nessus: {path} includes host {address!r}, not authorized target {host_ip!r}"
            )
        for item in host.findall("ReportItem"):
            index += 1
            severity = (item.get("severity") or "").strip()
            if severity == "0":
                continue  # inventory/scan metadata is not a vulnerability finding
            if severity not in SEVERITY:
                raise AdapterError(f"nessus: {path} item {index} has invalid severity")
            plugin_id = (item.get("pluginID") or "").strip()
            if not plugin_id:
                raise AdapterError(f"nessus: {path} item {index} has no pluginID")
            raw_port = (item.get("port") or "0").strip()
            try:
                port_number = int(raw_port)
            except ValueError as error:
                raise AdapterError(f"nessus: {path} item {index} has invalid port") from error
            if not 0 <= port_number <= 65535:
                raise AdapterError(f"nessus: {path} item {index} has invalid port")
            title = (item.get("pluginName") or f"Nessus plugin {plugin_id}").strip()
            description = (item.findtext("description") or title).strip()
            output = (item.findtext("plugin_output") or "").strip()
            cves = sorted(
                {
                    node.text.strip().upper()
                    for node in item.findall("cve")
                    if node.text and CVE.fullmatch(node.text.strip())
                }
            )
            findings.append(
                Finding.make(
                    host_ip=address,
                    port=port_number or None,
                    protocol=(item.get("protocol") or "").lower() or None,
                    tool="nessus",
                    tool_native_id=plugin_id,
                    title=title[:120],
                    description=description,
                    evidence=(f"{title}\n{output or description}").strip(),
                    cve_ids=cves,
                    cwe_ids=[],
                    reference_urls=[],
                    native_severity=SEVERITY[severity],
                    native_confidence=None,
                    first_seen="",
                    last_seen="",
                    provenance=Provenance(
                        tool="nessus", raw_path=str(path), record_index=index, run_id=run_id
                    ),
                )
            )
    return findings
