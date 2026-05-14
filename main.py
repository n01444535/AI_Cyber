#!/usr/bin/env python3
"""
AI Cyber Fusion Platform — CLI entry point.
Usage:
  python main.py nmap  <nmap_xml_file>   [--ioc]
  python main.py pcap  <pcap_file>
  python main.py full  <nmap_xml_file>   <pcap_file>  [--ioc]
  python main.py explain <nmap_xml_file> <ip_address>
  python main.py api
  python main.py demo
  python main.py history [--limit N]
"""

import argparse
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

DB_FILE_PATH = "cyber_platform.db"


def _save_session_to_db(session, report_paths: dict) -> None:
    """Persist a completed session + report paths to SQLite."""
    from backend.database import SessionRepository
    repository = SessionRepository(DB_FILE_PATH)
    repository.save_session(
        session,
        json_report_path=report_paths.get("json"),
        html_report_path=report_paths.get("html"),
    )


def run_nmap_analysis(nmap_xml_path: str, enable_ioc: bool) -> None:
    from backend.correlation.engine import correlate_alerts_into_stories
    from backend.ml.anomaly_detector import HostAnomalyDetector
    from backend.models import ScanSessionResult
    from backend.reports.report_generator import generate_report
    from backend.risk_engine import calculate_host_risk_profiles
    from backend.scanners.nmap_parser import convert_hosts_to_feature_dicts, parse_nmap_xml_file
    from backend.threat_intel.ioc_lookup import IOCLookupService, extract_unique_external_ips
    from frontend.dashboard import render_full_session_dashboard, print_quick_summary

    print(f"[*] Parsing Nmap XML: {nmap_xml_path}")
    scanned_hosts = parse_nmap_xml_file(nmap_xml_path)
    if not scanned_hosts:
        print("[!] No live hosts found.")
        return
    print(f"[+] Found {len(scanned_hosts)} live hosts.")

    host_feature_dicts = convert_hosts_to_feature_dicts(scanned_hosts)

    anomaly_detector = HostAnomalyDetector()
    anomaly_detector.train(host_feature_dicts)
    anomaly_results = anomaly_detector.detect_anomalies(host_feature_dicts)
    anomaly_count = sum(1 for r in anomaly_results if r.is_anomaly)
    print(f"[+] ML anomaly detection: {anomaly_count} anomalies found.")

    ioc_results = []
    if enable_ioc:
        print("[*] Running IOC lookups (this may take a moment)...")
        ioc_service = IOCLookupService()
        external_ips = extract_unique_external_ips(host_feature_dicts)
        ioc_results = ioc_service.lookup_indicators_in_bulk(external_ips[:20])
        malicious_count = sum(1 for r in ioc_results if r.is_malicious)
        print(f"[+] IOC lookup complete. {malicious_count} malicious indicators found.")

    attack_stories = correlate_alerts_into_stories([])
    host_profiles = calculate_host_risk_profiles(
        scanned_hosts=scanned_hosts,
        threat_alerts=[],
        anomaly_results=anomaly_results,
        ioc_results=ioc_results,
        attack_stories=attack_stories,
    )

    session = ScanSessionResult(
        session_id=str(uuid.uuid4())[:12],
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
        scanned_hosts=scanned_hosts,
        threat_alerts=[],
        host_risk_profiles=host_profiles,
        attack_stories=attack_stories,
        timeline_events=[],
        total_risk_score=max((p.risk_score for p in host_profiles), default=0.0),
        executive_summary=_build_summary(host_profiles, [], attack_stories),
        nmap_file_path=nmap_xml_path,
    )

    render_full_session_dashboard(session)
    report_paths = generate_report(session, "reports/")
    _save_session_to_db(session, report_paths)
    print(f"\n[+] Reports saved:")
    print(f"    JSON: {report_paths['json']}")
    print(f"    HTML: {report_paths['html']}")
    print(f"[+] Session {session.session_id} persisted to {DB_FILE_PATH}")


def run_pcap_analysis(pcap_file_path: str) -> None:
    from backend.correlation.engine import correlate_alerts_into_stories
    from backend.ml.anomaly_detector import TrafficAnomalyDetector
    from backend.models import ScanSessionResult
    from backend.packet_analyzer.pcap_parser import parse_pcap_file
    from backend.packet_analyzer.traffic_analyzer import (
        build_network_flows,
        detect_threats_in_traffic,
        extract_traffic_features_per_host,
    )
    from backend.reports.report_generator import generate_report
    from backend.risk_engine import calculate_host_risk_profiles
    from backend.threat_intel.ioc_lookup import IOCLookupService, extract_unique_external_ips
    from frontend.dashboard import render_full_session_dashboard

    print(f"[*] Parsing PCAP: {pcap_file_path}")
    packet_records = parse_pcap_file(pcap_file_path)
    print(f"[+] Parsed {len(packet_records)} packets.")

    network_flows = build_network_flows(packet_records)
    print(f"[+] Built {len(network_flows)} network flows.")

    print("[*] Detecting threats in traffic...")
    threat_alerts = detect_threats_in_traffic(packet_records, network_flows)
    print(f"[+] {len(threat_alerts)} threat alerts generated.")

    traffic_features = extract_traffic_features_per_host(packet_records, network_flows)
    anomaly_detector = TrafficAnomalyDetector()
    anomaly_detector.train(traffic_features)
    anomaly_results = anomaly_detector.detect_anomalies(traffic_features)
    anomaly_count = sum(1 for r in anomaly_results if r.is_anomaly)
    print(f"[+] ML anomaly detection: {anomaly_count} anomalies found.")

    print("[*] Correlating events into attack stories...")
    attack_stories = correlate_alerts_into_stories(threat_alerts)
    print(f"[+] {len(attack_stories)} attack story(ies) correlated.")

    host_profiles = calculate_host_risk_profiles(
        scanned_hosts=[],
        threat_alerts=threat_alerts,
        anomaly_results=anomaly_results,
        ioc_results=[],
        attack_stories=attack_stories,
    )

    all_timeline_events = []
    for story in attack_stories:
        all_timeline_events.extend(story.timeline_events)

    session = ScanSessionResult(
        session_id=str(uuid.uuid4())[:12],
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
        scanned_hosts=[],
        threat_alerts=threat_alerts,
        host_risk_profiles=host_profiles,
        attack_stories=attack_stories,
        timeline_events=all_timeline_events,
        total_risk_score=max((p.risk_score for p in host_profiles), default=0.0),
        executive_summary=_build_summary(host_profiles, threat_alerts, attack_stories),
        pcap_file_path=pcap_file_path,
    )

    render_full_session_dashboard(session)
    report_paths = generate_report(session, "reports/")
    _save_session_to_db(session, report_paths)
    print(f"\n[+] Reports saved:")
    print(f"    JSON: {report_paths['json']}")
    print(f"    HTML: {report_paths['html']}")
    print(f"[+] Session {session.session_id} persisted to {DB_FILE_PATH}")


def run_full_analysis(nmap_xml_path: str, pcap_file_path: str, enable_ioc: bool) -> None:
    from backend.correlation.engine import correlate_alerts_into_stories
    from backend.ml.anomaly_detector import HostAnomalyDetector, TrafficAnomalyDetector
    from backend.models import ScanSessionResult
    from backend.packet_analyzer.pcap_parser import parse_pcap_file
    from backend.packet_analyzer.traffic_analyzer import (
        build_network_flows,
        detect_threats_in_traffic,
        extract_traffic_features_per_host,
    )
    from backend.reports.report_generator import generate_report
    from backend.risk_engine import calculate_host_risk_profiles
    from backend.scanners.nmap_parser import convert_hosts_to_feature_dicts, parse_nmap_xml_file
    from backend.threat_intel.ioc_lookup import IOCLookupService, extract_unique_external_ips
    from frontend.dashboard import render_full_session_dashboard

    print(f"[*] Full analysis: {nmap_xml_path} + {pcap_file_path}")

    scanned_hosts = parse_nmap_xml_file(nmap_xml_path)
    print(f"[+] Nmap: {len(scanned_hosts)} hosts.")

    packet_records = parse_pcap_file(pcap_file_path)
    print(f"[+] PCAP: {len(packet_records)} packets.")

    network_flows = build_network_flows(packet_records)
    threat_alerts = detect_threats_in_traffic(packet_records, network_flows)
    print(f"[+] Threats detected: {len(threat_alerts)}.")

    host_scan_features = convert_hosts_to_feature_dicts(scanned_hosts)
    traffic_features   = extract_traffic_features_per_host(packet_records, network_flows)

    host_anomaly_detector    = HostAnomalyDetector()
    traffic_anomaly_detector = TrafficAnomalyDetector()
    host_anomaly_detector.train(host_scan_features)
    traffic_anomaly_detector.train(traffic_features)
    host_anomaly_results    = host_anomaly_detector.detect_anomalies(host_scan_features)
    traffic_anomaly_results = traffic_anomaly_detector.detect_anomalies(traffic_features)
    all_anomaly_results = host_anomaly_results + traffic_anomaly_results

    ioc_results = []
    if enable_ioc:
        print("[*] Running IOC lookups...")
        ioc_service = IOCLookupService()
        external_ips = extract_unique_external_ips(traffic_features)
        ioc_results = ioc_service.lookup_indicators_in_bulk(external_ips[:20])

    print("[*] Correlating attack stories...")
    attack_stories = correlate_alerts_into_stories(threat_alerts)

    host_profiles = calculate_host_risk_profiles(
        scanned_hosts=scanned_hosts,
        threat_alerts=threat_alerts,
        anomaly_results=all_anomaly_results,
        ioc_results=ioc_results,
        attack_stories=attack_stories,
    )

    all_timeline_events = []
    for story in attack_stories:
        all_timeline_events.extend(story.timeline_events)

    session = ScanSessionResult(
        session_id=str(uuid.uuid4())[:12],
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
        scanned_hosts=scanned_hosts,
        threat_alerts=threat_alerts,
        host_risk_profiles=host_profiles,
        attack_stories=attack_stories,
        timeline_events=all_timeline_events,
        total_risk_score=max((p.risk_score for p in host_profiles), default=0.0),
        executive_summary=_build_summary(host_profiles, threat_alerts, attack_stories),
        nmap_file_path=nmap_xml_path,
        pcap_file_path=pcap_file_path,
    )

    render_full_session_dashboard(session)
    report_paths = generate_report(session, "reports/")
    _save_session_to_db(session, report_paths)
    print(f"\n[+] Reports saved:")
    print(f"    JSON: {report_paths['json']}")
    print(f"    HTML: {report_paths['html']}")
    print(f"[+] Session {session.session_id} persisted to {DB_FILE_PATH}")


def run_host_explanation(nmap_xml_path: str, target_ip: str) -> None:
    from backend.correlation.engine import correlate_alerts_into_stories
    from backend.ml.anomaly_detector import HostAnomalyDetector
    from backend.models import ScanSessionResult
    from backend.risk_engine import calculate_host_risk_profiles
    from backend.scanners.nmap_parser import convert_hosts_to_feature_dicts, parse_nmap_xml_file
    from frontend.dashboard import render_host_explanation

    scanned_hosts = parse_nmap_xml_file(nmap_xml_path)
    host_feature_dicts = convert_hosts_to_feature_dicts(scanned_hosts)

    anomaly_detector = HostAnomalyDetector()
    anomaly_detector.train(host_feature_dicts)
    anomaly_results = anomaly_detector.detect_anomalies(host_feature_dicts)

    host_profiles = calculate_host_risk_profiles(
        scanned_hosts=scanned_hosts,
        threat_alerts=[],
        anomaly_results=anomaly_results,
        ioc_results=[],
        attack_stories=[],
    )

    session = ScanSessionResult(
        session_id="explain",
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
        scanned_hosts=scanned_hosts,
        threat_alerts=[],
        host_risk_profiles=host_profiles,
        attack_stories=[],
        timeline_events=[],
        total_risk_score=0.0,
        executive_summary="",
    )

    render_host_explanation(session, target_ip)


def run_demo_mode() -> None:
    from frontend.dashboard import render_full_session_dashboard
    from backend.models import (
        ScanSessionResult, ScannedHostRecord, PortRecord,
        ThreatAlertRecord, ThreatCategory, RiskLevel,
        CorrelatedAttackStory, AttackTimelineEvent, HostRiskProfile,
        AnomalyDetectionResult,
    )
    from backend.risk_engine import calculate_host_risk_profiles
    from backend.correlation.engine import correlate_alerts_into_stories

    print("[*] Running demo with synthetic data...")

    demo_hosts = [
        ScannedHostRecord(
            ip_address="192.168.1.50", hostname="srv-web-01",
            operating_system="Windows Server 2019", mac_address="00:50:56:aa:bb:01", mac_vendor="VMware",
            open_ports=[
                PortRecord(445, "tcp", "open", "microsoft-ds", "Windows", ""),
                PortRecord(3389, "tcp", "open", "ms-wbt-server", "", ""),
                PortRecord(80,   "tcp", "open", "http", "IIS", "10.0"),
            ],
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
        ),
        ScannedHostRecord(
            ip_address="192.168.1.20", hostname="db-server",
            operating_system="Ubuntu 22.04", mac_address="00:50:56:aa:bb:02", mac_vendor="VMware",
            open_ports=[
                PortRecord(3306, "tcp", "open", "mysql",      "MySQL", "8.0"),
                PortRecord(5432, "tcp", "open", "postgresql", "PostgreSQL", "14"),
                PortRecord(27017,"tcp", "open", "mongod",     "MongoDB", "6.0"),
                PortRecord(6379, "tcp", "open", "redis",      "Redis", "7.0"),
                PortRecord(22,   "tcp", "open", "ssh",        "OpenSSH", "8.9"),
            ],
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
        ),
        ScannedHostRecord(
            ip_address="10.0.0.1", hostname="router-gw",
            operating_system="Cisco IOS", mac_address="aa:bb:cc:dd:ee:ff", mac_vendor="Cisco",
            open_ports=[
                PortRecord(23,  "tcp", "open", "telnet", "", ""),
                PortRecord(161, "udp", "open", "snmp",   "", ""),
            ],
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    ]

    demo_alerts = [
        ThreatAlertRecord(
            alert_id="a1b2c3d4",
            source_ip="192.168.1.100",
            destination_ip="multiple",
            threat_category=ThreatCategory.PORT_SCAN,
            risk_level=RiskLevel.HIGH,
            confidence_score=0.92,
            description="Port scan: 192.168.1.100 probed 87 unique ports in 60s.",
            evidence=["Unique ports: 87", "SYN packets without ACK"],
            mitre_technique_id="T1046",
            mitre_technique_name="Network Service Discovery",
            mitre_tactic_id="TA0043",
            mitre_tactic_name="Reconnaissance",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
        ThreatAlertRecord(
            alert_id="e5f6g7h8",
            source_ip="192.168.1.100",
            destination_ip="192.168.1.50 (3 hosts)",
            threat_category=ThreatCategory.SMB_ENUM,
            risk_level=RiskLevel.HIGH,
            confidence_score=0.88,
            description="SMB enumeration: 192.168.1.100 sent 45 SMB packets to 3 hosts.",
            evidence=["SMB packet count: 45", "Unique targets: 3"],
            mitre_technique_id="T1021.002",
            mitre_technique_name="SMB/Windows Admin Shares",
            mitre_tactic_id="TA0008",
            mitre_tactic_name="Lateral Movement",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
        ThreatAlertRecord(
            alert_id="i9j0k1l2",
            source_ip="192.168.1.100",
            destination_ip="203.0.113.42",
            threat_category=ThreatCategory.BEACONING,
            risk_level=RiskLevel.CRITICAL,
            confidence_score=0.95,
            description="Beaconing: 192.168.1.100 sends periodic encrypted traffic to 203.0.113.42 every ~30s (CV=0.04).",
            evidence=["Connection count: 12", "Mean interval: 30.2s", "Interval CV: 0.04"],
            mitre_technique_id="T1071",
            mitre_technique_name="Application Layer Protocol",
            mitre_tactic_id="TA0011",
            mitre_tactic_name="Command and Control",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    ]

    demo_anomaly_results = [
        AnomalyDetectionResult(
            ip_address="192.168.1.100",
            anomaly_score=0.92,
            is_anomaly=True,
            contributing_features=["syn_packet_count=450 (mean=12)", "unique_destination_count=87 (mean=3)"],
        ),
        AnomalyDetectionResult(ip_address="192.168.1.50", anomaly_score=0.35, is_anomaly=False),
        AnomalyDetectionResult(ip_address="192.168.1.20", anomaly_score=0.28, is_anomaly=False),
    ]

    attack_stories = correlate_alerts_into_stories(demo_alerts)
    host_profiles = calculate_host_risk_profiles(
        scanned_hosts=demo_hosts,
        threat_alerts=demo_alerts,
        anomaly_results=demo_anomaly_results,
        ioc_results=[],
        attack_stories=attack_stories,
    )

    all_timeline_events = []
    for story in attack_stories:
        all_timeline_events.extend(story.timeline_events)

    session = ScanSessionResult(
        session_id="demo-" + str(uuid.uuid4())[:6],
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
        scanned_hosts=demo_hosts,
        threat_alerts=demo_alerts,
        host_risk_profiles=host_profiles,
        attack_stories=attack_stories,
        timeline_events=all_timeline_events,
        total_risk_score=max((p.risk_score for p in host_profiles), default=0.0),
        executive_summary=_build_summary(host_profiles, demo_alerts, attack_stories),
    )

    from backend.reports.report_generator import generate_report
    render_full_session_dashboard(session)
    report_paths = generate_report(session, "reports/")
    _save_session_to_db(session, report_paths)
    print(f"\n[+] Demo report saved:")
    print(f"    JSON: {report_paths['json']}")
    print(f"    HTML: {report_paths['html']}")
    print(f"[+] Session {session.session_id} persisted to {DB_FILE_PATH}")


def run_history_command(limit: int) -> None:
    from backend.database import SessionRepository
    from rich import box
    from rich.console import Console
    from rich.table import Table

    repository = SessionRepository(DB_FILE_PATH)
    session_summaries = repository.list_sessions(limit=limit)
    total_session_count = repository.count_sessions()

    console = Console()

    if not session_summaries:
        console.print("[yellow]No scan sessions found in the database.[/yellow]")
        console.print(f"[dim]Database: {DB_FILE_PATH}[/dim]")
        return

    history_table = Table(
        title=f"Scan History — {total_session_count} total session(s) | showing {len(session_summaries)}",
        box=box.ROUNDED,
        border_style="blue",
    )
    history_table.add_column("Session ID",    style="bold cyan",   min_width=14)
    history_table.add_column("Timestamp",     style="dim white",   min_width=22)
    history_table.add_column("Source",        style="dim white",   max_width=30)
    history_table.add_column("Hosts",         justify="right",     min_width=6)
    history_table.add_column("Alerts",        justify="right",     min_width=7)
    history_table.add_column("Stories",       justify="right",     min_width=8)
    history_table.add_column("Risk Score",    justify="right",     min_width=10)
    history_table.add_column("JSON Report",   style="dim",         max_width=40)

    for session_row in session_summaries:
        risk_score = session_row["total_risk_score"]
        if risk_score >= 80:
            score_display = f"[bold red]{risk_score:.0f}[/bold red]"
        elif risk_score >= 60:
            score_display = f"[bold orange3]{risk_score:.0f}[/bold orange3]"
        elif risk_score >= 40:
            score_display = f"[bold yellow]{risk_score:.0f}[/bold yellow]"
        else:
            score_display = f"[bold green]{risk_score:.0f}[/bold green]"

        source_file = session_row.get("nmap_file_path") or session_row.get("pcap_file_path") or "demo"
        json_report = session_row.get("json_report_path") or "—"

        history_table.add_row(
            session_row["session_id"],
            session_row["scan_timestamp"][:19],
            source_file,
            str(session_row["host_count"]),
            str(session_row["alert_count"]),
            str(session_row["story_count"]),
            score_display,
            json_report,
        )

    console.print(history_table)
    console.print(f"\n[dim]Database: {DB_FILE_PATH}[/dim]")
    console.print("[dim]Tip: python main.py history --limit 100  |  API: GET /sessions[/dim]")


def run_api_server() -> None:
    import uvicorn
    print("[*] Starting AI Cyber Fusion API server on http://localhost:8000")
    print("[*] API docs: http://localhost:8000/docs")
    uvicorn.run("backend.api.main:app", host="0.0.0.0", port=8000, reload=True)


def _build_summary(host_profiles, threat_alerts, attack_stories) -> str:
    from backend.models import RiskLevel
    critical_count = sum(1 for p in host_profiles if p.risk_level == RiskLevel.CRITICAL)
    high_count     = sum(1 for p in host_profiles if p.risk_level == RiskLevel.HIGH)
    if critical_count == 0 and not threat_alerts:
        return "No significant threats detected."
    parts = []
    if critical_count > 0:
        parts.append(f"{critical_count} critical-risk host(s) require immediate attention.")
    if high_count > 0:
        parts.append(f"{high_count} high-risk host(s) identified.")
    if threat_alerts:
        parts.append(f"{len(threat_alerts)} threat alert(s) generated.")
    if attack_stories:
        parts.append(f"{len(attack_stories)} correlated attack story(ies) detected.")
    return " ".join(parts)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AI Cyber Fusion Platform — Autonomous Threat Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    nmap_parser = subparsers.add_parser("nmap", help="Analyze Nmap XML scan file")
    nmap_parser.add_argument("xml_file", help="Path to Nmap XML output file")
    nmap_parser.add_argument("--ioc", action="store_true", help="Enable IOC threat intel lookups")

    pcap_parser = subparsers.add_parser("pcap", help="Analyze PCAP traffic file")
    pcap_parser.add_argument("pcap_file", help="Path to PCAP or PCAPNG file")

    full_parser = subparsers.add_parser("full", help="Full analysis: Nmap + PCAP")
    full_parser.add_argument("xml_file",  help="Path to Nmap XML output file")
    full_parser.add_argument("pcap_file", help="Path to PCAP or PCAPNG file")
    full_parser.add_argument("--ioc", action="store_true", help="Enable IOC threat intel lookups")

    explain_parser = subparsers.add_parser("explain", help="AI explanation for a specific host IP")
    explain_parser.add_argument("xml_file",   help="Path to Nmap XML output file")
    explain_parser.add_argument("ip_address", help="IP address to explain")

    subparsers.add_parser("api",  help="Start FastAPI REST server on port 8000")
    subparsers.add_parser("demo", help="Run demo with synthetic attack scenario")

    history_parser = subparsers.add_parser("history", help="List all past scan sessions from the database")
    history_parser.add_argument("--limit", type=int, default=50, help="Maximum number of sessions to show (default: 50)")

    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()

    if args.command == "nmap":
        run_nmap_analysis(args.xml_file, enable_ioc=args.ioc)
    elif args.command == "pcap":
        run_pcap_analysis(args.pcap_file)
    elif args.command == "full":
        run_full_analysis(args.xml_file, args.pcap_file, enable_ioc=args.ioc)
    elif args.command == "explain":
        run_host_explanation(args.xml_file, args.ip_address)
    elif args.command == "api":
        run_api_server()
    elif args.command == "demo":
        run_demo_mode()
    elif args.command == "history":
        run_history_command(limit=args.limit)


if __name__ == "__main__":
    main()
