import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from backend.models import PortRecord, ScannedHostRecord


def parse_nmap_xml_file(xml_file_path: str) -> list[ScannedHostRecord]:
    file_path = Path(xml_file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"Nmap XML file not found: {xml_file_path}")

    xml_tree = ET.parse(file_path)
    xml_root = xml_tree.getroot()
    scanned_hosts = []

    for host_element in xml_root.findall("host"):
        host_record = _extract_host_record(host_element)
        if host_record:
            scanned_hosts.append(host_record)

    return scanned_hosts


def _extract_host_record(host_element: ET.Element) -> ScannedHostRecord | None:
    status_element = host_element.find("status")
    if status_element is None or status_element.get("state") != "up":
        return None

    ip_address = _extract_ip_address(host_element)
    if not ip_address:
        return None

    hostname = _extract_hostname(host_element)
    operating_system = _extract_os_name(host_element)
    mac_address, mac_vendor = _extract_mac_info(host_element)
    open_ports = _extract_open_ports(host_element)
    scan_timestamp = datetime.utcnow().isoformat()

    return ScannedHostRecord(
        ip_address=ip_address,
        hostname=hostname,
        operating_system=operating_system,
        mac_address=mac_address,
        mac_vendor=mac_vendor,
        open_ports=open_ports,
        raw_nmap_status="up",
        scan_timestamp=scan_timestamp,
    )


def _extract_ip_address(host_element: ET.Element) -> str:
    for address_element in host_element.findall("address"):
        if address_element.get("addrtype") == "ipv4":
            return address_element.get("addr", "")
    return ""


def _extract_hostname(host_element: ET.Element) -> str:
    hostnames_element = host_element.find("hostnames")
    if hostnames_element is None:
        return ""
    hostname_element = hostnames_element.find("hostname")
    if hostname_element is None:
        return ""
    return hostname_element.get("name", "")


def _extract_os_name(host_element: ET.Element) -> str:
    os_element = host_element.find("os")
    if os_element is None:
        return "Unknown"
    osmatch_element = os_element.find("osmatch")
    if osmatch_element is None:
        return "Unknown"
    return osmatch_element.get("name", "Unknown")


def _extract_mac_info(host_element: ET.Element) -> tuple[str, str]:
    for address_element in host_element.findall("address"):
        if address_element.get("addrtype") == "mac":
            mac_address = address_element.get("addr", "")
            mac_vendor = address_element.get("vendor", "Unknown")
            return mac_address, mac_vendor
    return "", "Unknown"


def _extract_open_ports(host_element: ET.Element) -> list[PortRecord]:
    open_ports: list[PortRecord] = []
    ports_element = host_element.find("ports")
    if ports_element is None:
        return open_ports

    for port_element in ports_element.findall("port"):
        port_record = _extract_single_port(port_element)
        if port_record:
            open_ports.append(port_record)

    return open_ports


def _extract_single_port(port_element: ET.Element) -> PortRecord | None:
    state_element = port_element.find("state")
    if state_element is None or state_element.get("state") != "open":
        return None

    port_number = int(port_element.get("portid", 0))
    protocol = port_element.get("protocol", "tcp")

    service_element = port_element.find("service")
    service_name = ""
    product = ""
    version = ""
    extra_info = ""
    tunnel = ""

    if service_element is not None:
        service_name = service_element.get("name", "")
        product = service_element.get("product", "")
        version = service_element.get("version", "")
        extra_info = service_element.get("extrainfo", "")
        tunnel = service_element.get("tunnel", "")

    script_outputs = _extract_nse_script_outputs(port_element)

    return PortRecord(
        port_number=port_number,
        protocol=protocol,
        state="open",
        service_name=service_name,
        product=product,
        version=version,
        extra_info=extra_info,
        tunnel=tunnel,
        script_outputs=script_outputs,
    )


def _extract_nse_script_outputs(port_element: ET.Element) -> list[dict]:
    script_results = []
    for script_element in port_element.findall("script"):
        script_id = script_element.get("id", "")
        script_output = script_element.get("output", "")
        if script_id:
            script_results.append({"id": script_id, "output": script_output})
    return script_results


def convert_hosts_to_feature_dicts(scanned_hosts: list[ScannedHostRecord]) -> list[dict]:
    from backend.constants import (
        HIGH_RISK_PORTS, CRITICAL_RISK_PORTS, REMOTE_ACCESS_PORTS,
        DATABASE_PORTS, FILESHARE_PORTS, WEB_PORTS, MAIL_PORTS,
        CLEARTEXT_PORTS, ADMIN_PORTS,
    )

    feature_records = []
    for host in scanned_hosts:
        port_numbers = {port.port_number for port in host.open_ports}
        feature_records.append({
            "ip_address": host.ip_address,
            "hostname": host.hostname,
            "open_port_count": len(port_numbers),
            "high_risk_port_count": len(port_numbers & HIGH_RISK_PORTS),
            "critical_port_count": len(port_numbers & CRITICAL_RISK_PORTS),
            "remote_access_port_count": len(port_numbers & REMOTE_ACCESS_PORTS),
            "database_port_count": len(port_numbers & DATABASE_PORTS),
            "fileshare_port_count": len(port_numbers & FILESHARE_PORTS),
            "web_port_count": len(port_numbers & WEB_PORTS),
            "mail_port_count": len(port_numbers & MAIL_PORTS),
            "cleartext_port_count": len(port_numbers & CLEARTEXT_PORTS),
            "admin_port_count": len(port_numbers & ADMIN_PORTS),
            "has_smb": int(445 in port_numbers),
            "has_rdp": int(3389 in port_numbers),
            "has_ssh": int(22 in port_numbers),
            "has_telnet": int(23 in port_numbers),
            "has_ftp": int(21 in port_numbers),
            "has_rdp_vnc": int(bool({3389, 5900} & port_numbers)),
            "has_db_exposed": int(bool(DATABASE_PORTS & port_numbers)),
            "has_docker_api": int(bool({2375, 2376} & port_numbers)),
        })
    return feature_records
