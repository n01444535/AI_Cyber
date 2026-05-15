#!/usr/bin/env python3
"""
AI Cyber Fusion Platform — Autonomous Threat Detection & SOC-style Analysis

  sudo python3 main.py full [--target CIDR] [--interface IF] [--duration S] [--ioc]
  python3 main.py analyze   --nmap <xml> [--pcap <pcap>] [--ioc]
  python3 main.py analyze   --pcap <pcap>
  python3 main.py nmap      <nmap_xml>   [--ioc]
  python3 main.py pcap      <pcap_file>
  python3 main.py demo
  python3 main.py explain   <nmap_xml>  <ip_address>
  python3 main.py history   [--limit N]
  python3 main.py api
"""

import argparse
import uuid
from datetime import datetime, timezone

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
    from backend.constants import IOC_LOOKUP_MAX_EXTERNAL_IPS
    from backend.correlation.engine import correlate_alerts_into_stories
    from backend.ml.anomaly_detector import HostAnomalyDetector
    from backend.models import ScanSessionResult
    from backend.reports.report_generator import generate_report
    from backend.risk_engine import calculate_host_risk_profiles
    from backend.scanners.nmap_parser import convert_hosts_to_feature_dicts, parse_nmap_xml_file
    from backend.threat_intel.ioc_lookup import IOCLookupService, extract_unique_external_ips
    from frontend.dashboard import render_full_session_dashboard

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
        ioc_results = ioc_service.lookup_indicators_in_bulk(external_ips[:IOC_LOOKUP_MAX_EXTERNAL_IPS])
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
    print("\n[+] Reports saved:")
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
    print("\n[+] Reports saved:")
    print(f"    JSON: {report_paths['json']}")
    print(f"    HTML: {report_paths['html']}")
    print(f"[+] Session {session.session_id} persisted to {DB_FILE_PATH}")


def run_analyze_files(nmap_xml_path: str | None, pcap_file_path: str | None, enable_ioc: bool) -> None:
    if nmap_xml_path and not pcap_file_path:
        run_nmap_analysis(nmap_xml_path, enable_ioc=enable_ioc)
        return
    if pcap_file_path and not nmap_xml_path:
        run_pcap_analysis(pcap_file_path)
        return
    _run_combined_analysis(nmap_xml_path, pcap_file_path, enable_ioc)


def _run_combined_analysis(
    nmap_xml_path: str,
    pcap_file_path: str,
    enable_ioc: bool,
    scanner_context=None,
) -> None:
    from backend.constants import IOC_LOOKUP_MAX_EXTERNAL_IPS
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

    print(f"[*] Analyzing: {nmap_xml_path} + {pcap_file_path}")

    scanned_hosts = parse_nmap_xml_file(nmap_xml_path)
    print(f"[+] Nmap: {len(scanned_hosts)} hosts.")

    packet_records = parse_pcap_file(pcap_file_path)
    print(f"[+] PCAP: {len(packet_records)} packets.")

    network_flows = build_network_flows(packet_records)
    all_detected_alerts = detect_threats_in_traffic(packet_records, network_flows)
    print(f"[+] Threats detected: {len(all_detected_alerts)}.")

    active_threat_alerts = all_detected_alerts
    suppressed_alerts = []
    if scanner_context is not None:
        from backend.context.suppression_engine import apply_scanner_suppression
        active_threat_alerts, suppressed_alerts = apply_scanner_suppression(
            all_detected_alerts, scanner_context
        )
        if suppressed_alerts:
            print(
                f"[*] Suppressed {len(suppressed_alerts)} scanner-generated alert(s) "
                f"from risk scoring (source: {scanner_context.scanner_host_ip})."
            )

    host_scan_features = convert_hosts_to_feature_dicts(scanned_hosts)
    traffic_features = extract_traffic_features_per_host(packet_records, network_flows)

    host_anomaly_detector = HostAnomalyDetector()
    traffic_anomaly_detector = TrafficAnomalyDetector()
    host_anomaly_detector.train(host_scan_features)
    traffic_anomaly_detector.train(traffic_features)
    host_anomaly_results = host_anomaly_detector.detect_anomalies(host_scan_features)
    traffic_anomaly_results = traffic_anomaly_detector.detect_anomalies(traffic_features)
    all_anomaly_results = host_anomaly_results + traffic_anomaly_results

    ioc_results = []
    if enable_ioc:
        print("[*] Running IOC lookups...")
        ioc_service = IOCLookupService()
        external_ips = extract_unique_external_ips(traffic_features)
        ioc_results = ioc_service.lookup_indicators_in_bulk(external_ips[:IOC_LOOKUP_MAX_EXTERNAL_IPS])

    print("[*] Correlating attack stories...")
    attack_stories = correlate_alerts_into_stories(active_threat_alerts)

    host_profiles = calculate_host_risk_profiles(
        scanned_hosts=scanned_hosts,
        threat_alerts=active_threat_alerts,
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
        threat_alerts=active_threat_alerts,
        host_risk_profiles=host_profiles,
        attack_stories=attack_stories,
        timeline_events=all_timeline_events,
        total_risk_score=max((p.risk_score for p in host_profiles), default=0.0),
        executive_summary=_build_summary(host_profiles, active_threat_alerts, attack_stories),
        nmap_file_path=nmap_xml_path,
        pcap_file_path=pcap_file_path,
        suppressed_alerts=suppressed_alerts,
        scanner_host_ip=scanner_context.scanner_host_ip if scanner_context else "",
    )

    render_full_session_dashboard(session)
    report_paths = generate_report(session, "reports/")
    _save_session_to_db(session, report_paths)
    print("\n[+] Reports saved:")
    print(f"    JSON: {report_paths['json']}")
    print(f"    HTML: {report_paths['html']}")
    print(f"[+] Session {session.session_id} persisted to {DB_FILE_PATH}")


def run_full_autonomous(
    target: str | None,
    interface: str | None,
    duration: int,
    enable_ioc: bool,
    ignore_scanner_source: bool = True,
) -> None:
    import time
    from concurrent.futures import ThreadPoolExecutor

    from backend.context.scanner_context import build_scanner_context
    from backend.packet_analyzer.live_capture import (
        capture_live_traffic,
        detect_default_interface,
        detect_local_network,
    )
    from backend.scanners.nmap_runner import run_nmap_scan

    resolved_target = target or detect_local_network()
    resolved_interface = interface or detect_default_interface()

    print(f"[*] Target network  : {resolved_target}")
    print(f"[*] Interface       : {resolved_interface}")
    print(f"[*] Capture duration: {duration}s")
    print("[*] Running Nmap scan and live capture concurrently...")

    xml_path: list[str] = [None]
    pcap_path: list[str] = [None]
    scan_start_time = time.time()

    def do_nmap_scan() -> None:
        xml_path[0] = run_nmap_scan(resolved_target)
        print(f"[+] Nmap complete → {xml_path[0]}")

    def do_live_capture() -> None:
        pcap_path[0] = capture_live_traffic(resolved_interface, duration)
        print(f"[+] Capture complete → {pcap_path[0]}")

    with ThreadPoolExecutor(max_workers=2) as pool:
        nmap_future = pool.submit(do_nmap_scan)
        capture_future = pool.submit(do_live_capture)
        nmap_future.result()
        capture_future.result()

    scan_end_time = time.time()

    scanner_context = None
    if ignore_scanner_source:
        scanner_context = build_scanner_context(
            scan_start_time=scan_start_time,
            scan_end_time=scan_end_time,
        )
        print(f"[*] Scanner suppression active — self-generated alerts from {scanner_context.scanner_host_ip} will be downgraded.")

    _run_combined_analysis(xml_path[0], pcap_path[0], enable_ioc, scanner_context=scanner_context)


def run_host_explanation(nmap_xml_path: str, target_ip: str) -> None:
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
    from backend.analyst.recommendations import get_false_positive_explanations, get_recommended_actions
    from backend.correlation.engine import correlate_alerts_into_stories
    from backend.models import (
        AnomalyDetectionResult,
        PortRecord,
        RiskLevel,
        ScanSessionResult,
        ScannedHostRecord,
        ThreatAlertRecord,
        ThreatCategory,
    )
    from backend.risk_engine import calculate_host_risk_profiles
    from frontend.dashboard import render_full_session_dashboard

    print("[*] Running demo with synthetic data...")

    demo_hosts = [
        ScannedHostRecord(
            ip_address="xxx.xxx.x.x",
            hostname="srv-web-01",
            operating_system="Windows Server 2019",
            mac_address="00:50:56:aa:bb:01",
            mac_vendor="VMware",
            open_ports=[
                PortRecord(445, "tcp", "open", "microsoft-ds", "Windows", ""),
                PortRecord(3389, "tcp", "open", "ms-wbt-server", "", ""),
                PortRecord(80, "tcp", "open", "http", "IIS", "10.0"),
            ],
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
        ),
        ScannedHostRecord(
            ip_address="xxx.xxx.x.x",
            hostname="db-server",
            operating_system="Ubuntu 22.04",
            mac_address="00:50:56:aa:bb:02",
            mac_vendor="VMware",
            open_ports=[
                PortRecord(3306, "tcp", "open", "mysql", "MySQL", "8.0"),
                PortRecord(5432, "tcp", "open", "postgresql", "PostgreSQL", "14"),
                PortRecord(27017, "tcp", "open", "mongod", "MongoDB", "6.0"),
                PortRecord(6379, "tcp", "open", "redis", "Redis", "7.0"),
                PortRecord(22, "tcp", "open", "ssh", "OpenSSH", "8.9"),
            ],
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
        ),
        ScannedHostRecord(
            ip_address="xxx.xxx.x.x",
            hostname="router-gw",
            operating_system="Cisco IOS",
            mac_address="aa:bb:cc:dd:ee:ff",
            mac_vendor="Cisco",
            open_ports=[
                PortRecord(23, "tcp", "open", "telnet", "", ""),
                PortRecord(161, "udp", "open", "snmp", "", ""),
            ],
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    ]

    demo_alerts = [
        ThreatAlertRecord(
            alert_id="a1b2c3d4",
            source_ip="xxx.xxx.x.x",
            destination_ip="multiple",
            threat_category=ThreatCategory.PORT_SCAN,
            risk_level=RiskLevel.HIGH,
            confidence_score=0.92,
            description="Port scan: xxx.xxx.x.x probed 87 unique ports in 60s.",
            evidence=["Unique ports: 87", "SYN packets without ACK", "Time window: 60s"],
            possible_false_positive=get_false_positive_explanations(ThreatCategory.PORT_SCAN),
            recommended_actions=get_recommended_actions(ThreatCategory.PORT_SCAN),
            mitre_technique_id="T1046",
            mitre_technique_name="Network Service Discovery",
            mitre_tactic_id="TA0043",
            mitre_tactic_name="Reconnaissance",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
        ThreatAlertRecord(
            alert_id="e5f6g7h8",
            source_ip="xxx.xxx.x.x",
            destination_ip="xxx.xxx.x.x (3 hosts)",
            threat_category=ThreatCategory.SMB_ENUM,
            risk_level=RiskLevel.HIGH,
            confidence_score=0.88,
            description="SMB enumeration: xxx.xxx.x.x sent 45 SMB packets to 3 hosts.",
            evidence=["SMB packet count: 45", "Unique targets: 3", "Protocols: SMB1, SMB2"],
            possible_false_positive=get_false_positive_explanations(ThreatCategory.SMB_ENUM),
            recommended_actions=get_recommended_actions(ThreatCategory.SMB_ENUM),
            mitre_technique_id="T1021.002",
            mitre_technique_name="SMB/Windows Admin Shares",
            mitre_tactic_id="TA0008",
            mitre_tactic_name="Lateral Movement",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
        ThreatAlertRecord(
            alert_id="i9j0k1l2",
            source_ip="xxx.xxx.x.x",
            destination_ip="xxx.xxx.x.x",
            threat_category=ThreatCategory.BEACONING,
            risk_level=RiskLevel.CRITICAL,
            confidence_score=0.95,
            description="Beaconing / C2 behavior detected: xxx.xxx.x.x sends highly periodic traffic to xxx.xxx.x.x:443 every ~30s (interval CV=0.04, byte-size CV=0.06).",
            evidence=[
                "Connection count: 12",
                "Mean interval: 30.2s",
                "Interval CV (lower = more periodic): 0.04",
                "Byte-size CV: 0.06 — consistent payload size, stronger C2 indicator",
            ],
            possible_false_positive=get_false_positive_explanations(ThreatCategory.BEACONING),
            recommended_actions=get_recommended_actions(ThreatCategory.BEACONING),
            mitre_technique_id="T1071",
            mitre_technique_name="Application Layer Protocol",
            mitre_tactic_id="TA0011",
            mitre_tactic_name="Command and Control",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    ]

    demo_anomaly_results = [
        AnomalyDetectionResult(
            ip_address="xxx.xxx.x.x",
            anomaly_score=0.92,
            is_anomaly=True,
            contributing_features=[
                "syn_packet_count=450 (mean=12)",
                "unique_destination_count=87 (mean=3)",
            ],
        ),
        AnomalyDetectionResult(ip_address="xxx.xxx.x.x", anomaly_score=0.35, is_anomaly=False),
        AnomalyDetectionResult(ip_address="xxx.xxx.x.x", anomaly_score=0.28, is_anomaly=False),
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
    print("\n[+] Demo report saved:")
    print(f"    JSON: {report_paths['json']}")
    print(f"    HTML: {report_paths['html']}")
    print(f"[+] Session {session.session_id} persisted to {DB_FILE_PATH}")


def run_baseline_command(pcap_path: str, output_path: str) -> None:
    from backend.baseline.baseline_builder import build_baseline_from_pcap

    print(f"[*] Building baseline from: {pcap_path}")
    baseline = build_baseline_from_pcap(pcap_path, output_path)
    print(f"[+] Baseline built from {baseline['host_count']} hosts → {output_path}")
    print(f"    Global mean bytes_sent : {baseline['global']['bytes_sent']['mean']:,.0f}")
    print(f"    Global mean unique_dsts: {baseline['global']['unique_destination_count']['mean']:.1f}")


def run_compare_command(pcap_path: str, baseline_path: str) -> None:
    from backend.baseline.baseline_compare import compare_pcap_to_baseline
    from rich.console import Console
    from rich.table import Table
    from rich import box

    console = Console()
    print(f"[*] Comparing: {pcap_path}")
    print(f"[*] Baseline : {baseline_path}")
    deviations = compare_pcap_to_baseline(pcap_path, baseline_path)

    if not deviations:
        console.print("[green][+] No significant deviations detected vs baseline.[/green]")
        return

    deviation_table = Table(
        title=f"Baseline Deviations — {len(deviations)} finding(s)",
        box=box.ROUNDED,
        border_style="yellow",
    )
    deviation_table.add_column("Host IP", style="bold cyan", min_width=15)
    deviation_table.add_column("Metric", style="white", min_width=28)
    deviation_table.add_column("Observed", justify="right", min_width=14)
    deviation_table.add_column("Baseline Mean", justify="right", min_width=14)
    deviation_table.add_column("× Threshold", justify="right", min_width=12)

    for finding in deviations:
        factor = finding["deviation_factor"]
        factor_display = (
            f"[bold red]{factor:.1f}×[/bold red]"
            if factor >= 5
            else f"[bold yellow]{factor:.1f}×[/bold yellow]"
        )
        deviation_table.add_row(
            finding["host_ip"],
            finding["label"],
            f"{finding['observed_value']:,.0f}",
            f"{finding['baseline_mean']:,.0f}",
            factor_display,
        )

    console.print(deviation_table)


def run_history_command(limit: int) -> None:
    from backend.constants import RISK_SCORE_CRITICAL_MIN, RISK_SCORE_HIGH_MIN, RISK_SCORE_MEDIUM_MIN
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
    history_table.add_column("Session ID", style="bold cyan", min_width=14)
    history_table.add_column("Timestamp", style="dim white", min_width=22)
    history_table.add_column("Source", style="dim white", max_width=30)
    history_table.add_column("Hosts", justify="right", min_width=6)
    history_table.add_column("Alerts", justify="right", min_width=7)
    history_table.add_column("Stories", justify="right", min_width=8)
    history_table.add_column("Risk Score", justify="right", min_width=10)
    history_table.add_column("JSON Report", style="dim", max_width=40)

    for session_row in session_summaries:
        risk_score = session_row["total_risk_score"]
        if risk_score >= RISK_SCORE_CRITICAL_MIN:
            score_display = f"[bold red]{risk_score:.0f}[/bold red]"
        elif risk_score >= RISK_SCORE_HIGH_MIN:
            score_display = f"[bold orange3]{risk_score:.0f}[/bold orange3]"
        elif risk_score >= RISK_SCORE_MEDIUM_MIN:
            score_display = f"[bold yellow]{risk_score:.0f}[/bold yellow]"
        else:
            score_display = f"[bold green]{risk_score:.0f}[/bold green]"

        source_file = (
            session_row.get("nmap_file_path") or session_row.get("pcap_file_path") or "demo"
        )
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
    high_count = sum(1 for p in host_profiles if p.risk_level == RiskLevel.HIGH)
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


_HELP_EPILOG = """
examples:
  sudo python3 main.py full
  sudo python3 main.py full --target xxx.xxx.x.x/24 --interface en0 --duration 120 --ioc
  sudo python3 main.py full --include-self-alerts          # disable scanner false-positive suppression
  python3 main.py analyze --nmap samples/nmap/sample_scan.xml --pcap samples/pcaps/capture.pcap
  python3 main.py analyze --nmap samples/nmap/sample_scan.xml --ioc
  python3 main.py analyze --pcap samples/pcaps/capture.pcap
  python3 main.py nmap   samples/nmap/sample_scan.xml --ioc
  python3 main.py pcap   samples/pcaps/capture.pcap
  python3 main.py demo
  python3 main.py explain samples/nmap/sample_scan.xml xxx.xxx.x.x
  python3 main.py baseline samples/pcaps/normal_traffic.pcap --output baseline.json
  python3 main.py compare  samples/pcaps/suspicious.pcap    --baseline baseline.json
  python3 main.py history --limit 20
  python3 main.py api
"""


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python main.py",
        description="AI Cyber Fusion Platform — Autonomous Threat Detection & SOC-style Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_HELP_EPILOG,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    nmap_parser = subparsers.add_parser("nmap", help="Analyze Nmap XML scan file")
    nmap_parser.add_argument("xml_file", help="Path to Nmap XML output file")
    nmap_parser.add_argument("--ioc", action="store_true", help="Enable IOC threat intel lookups")

    pcap_parser = subparsers.add_parser("pcap", help="Analyze PCAP traffic file")
    pcap_parser.add_argument("pcap_file", help="Path to PCAP or PCAPNG file")

    full_parser = subparsers.add_parser(
        "full", help="Autonomous real-time scan: detect network, run Nmap, capture traffic"
    )
    full_parser.add_argument(
        "--target", metavar="CIDR",
        help="Target network CIDR (default: auto-detect local /24)",
    )
    full_parser.add_argument(
        "--interface", metavar="IF",
        help="Network interface for live capture (default: auto-detect)",
    )
    full_parser.add_argument(
        "--duration", type=int, default=60, metavar="SECONDS",
        help="Packet capture duration in seconds (default: 60)",
    )
    full_parser.add_argument("--ioc", action="store_true", help="Enable IOC threat intel lookups")
    full_parser.add_argument(
        "--include-self-alerts",
        action="store_true",
        dest="include_self_alerts",
        help="Include self-generated Nmap traffic in threat scoring (disables scanner suppression)",
    )

    analyze_parser = subparsers.add_parser(
        "analyze", help="File-based analysis: Nmap XML and/or PCAP"
    )
    analyze_parser.add_argument("--nmap", metavar="XML_FILE", help="Path to Nmap XML output file")
    analyze_parser.add_argument("--pcap", metavar="PCAP_FILE", help="Path to PCAP or PCAPNG file")
    analyze_parser.add_argument(
        "--ioc", action="store_true", help="Enable IOC threat intel lookups"
    )

    explain_parser = subparsers.add_parser("explain", help="AI explanation for a specific host IP")
    explain_parser.add_argument("xml_file", help="Path to Nmap XML output file")
    explain_parser.add_argument("ip_address", help="IP address to explain")

    subparsers.add_parser("api", help="Start FastAPI REST server on port 8000")
    subparsers.add_parser("demo", help="Run demo with synthetic attack scenario")

    baseline_parser = subparsers.add_parser(
        "baseline", help="Build a traffic baseline from a normal-traffic PCAP"
    )
    baseline_parser.add_argument("pcap_file", help="Path to normal-traffic PCAP file")
    baseline_parser.add_argument(
        "--output", metavar="JSON_FILE", default="baseline.json",
        help="Output path for the baseline JSON (default: baseline.json)",
    )

    compare_parser = subparsers.add_parser(
        "compare", help="Compare a PCAP against a saved baseline to detect deviations"
    )
    compare_parser.add_argument("pcap_file", help="Path to PCAP file to compare")
    compare_parser.add_argument(
        "--baseline", metavar="JSON_FILE", default="baseline.json",
        help="Path to baseline JSON produced by 'baseline' command (default: baseline.json)",
    )

    history_parser = subparsers.add_parser(
        "history", help="List all past scan sessions from the database"
    )
    history_parser.add_argument(
        "--limit", type=int, default=50, help="Maximum number of sessions to show (default: 50)"
    )

    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()

    if args.command == "nmap":
        run_nmap_analysis(args.xml_file, enable_ioc=args.ioc)
    elif args.command == "pcap":
        run_pcap_analysis(args.pcap_file)
    elif args.command == "full":
        run_full_autonomous(
            target=args.target,
            interface=args.interface,
            duration=args.duration,
            enable_ioc=args.ioc,
            ignore_scanner_source=not args.include_self_alerts,
        )
    elif args.command == "analyze":
        if not args.nmap and not args.pcap:
            print("[!] analyze requires at least one of --nmap or --pcap.")
            return
        run_analyze_files(args.nmap, args.pcap, enable_ioc=args.ioc)
    elif args.command == "explain":
        run_host_explanation(args.xml_file, args.ip_address)
    elif args.command == "api":
        run_api_server()
    elif args.command == "demo":
        run_demo_mode()
    elif args.command == "baseline":
        run_baseline_command(args.pcap_file, args.output)
    elif args.command == "compare":
        run_compare_command(args.pcap_file, args.baseline)
    elif args.command == "history":
        run_history_command(limit=args.limit)


if __name__ == "__main__":
    main()
