import statistics
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone

from backend.constants import (
    BEACONING_INTERVAL_VARIANCE_MAX,
    BEACONING_MIN_OCCURRENCES,
    BRUTE_FORCE_ATTEMPT_MIN,
    DNS_QUERY_BURST_MIN,
    DNS_QUERY_TIME_WINDOW_SECONDS,
    EXFIL_BYTES_THRESHOLD,
    LATERAL_MOVEMENT_MIN_HOSTS,
    MITRE_TACTIC_C2,
    MITRE_TACTIC_EXFILTRATION,
    MITRE_TACTIC_LATERAL_MOVE,
    MITRE_TACTIC_RECON,
    MITRE_TECHNIQUE_BEACONING,
    MITRE_TECHNIQUE_BRUTE_FORCE,
    MITRE_TECHNIQUE_DNS_TUNNEL,
    MITRE_TECHNIQUE_EXFIL_C2,
    MITRE_TECHNIQUE_PORT_SCAN,
    MITRE_TECHNIQUE_SMB_LATERAL,
    PORT_SCAN_TIME_WINDOW_SECONDS,
    PORT_SCAN_UNIQUE_PORT_MIN,
    SMB_ENUM_PACKET_MIN,
    REMOTE_ACCESS_PORTS,
)
from backend.models import (
    NetworkFlowRecord,
    ParsedPacketRecord,
    RiskLevel,
    ThreatAlertRecord,
    ThreatCategory,
)


def build_network_flows(packet_records: list[ParsedPacketRecord]) -> list[NetworkFlowRecord]:
    flow_buckets: dict[tuple, list[ParsedPacketRecord]] = defaultdict(list)

    for packet in packet_records:
        flow_key = (
            packet.source_ip,
            packet.destination_ip,
            packet.source_port,
            packet.destination_port,
            packet.protocol,
        )
        flow_buckets[flow_key].append(packet)

    network_flows: list[NetworkFlowRecord] = []
    for flow_key, flow_packets in flow_buckets.items():
        flow_record = _aggregate_flow(flow_key, flow_packets)
        network_flows.append(flow_record)

    return sorted(network_flows, key=lambda flow: flow.byte_count, reverse=True)


def _aggregate_flow(flow_key: tuple, flow_packets: list[ParsedPacketRecord]) -> NetworkFlowRecord:
    source_ip, destination_ip, source_port, destination_port, protocol = flow_key
    timestamps = [packet.timestamp for packet in flow_packets]
    first_seen = min(timestamps)
    last_seen = max(timestamps)
    duration_seconds = max(last_seen - first_seen, 0.001)

    total_bytes = sum(packet.packet_length for packet in flow_packets)
    syn_count = sum(packet.tcp_flags_syn for packet in flow_packets)
    rst_count = sum(packet.tcp_flags_rst for packet in flow_packets)

    sample_infos = [p.info_string for p in flow_packets[:5] if p.info_string]
    http_uris = list({p.http_uri for p in flow_packets if p.http_uri})[:10]
    http_status_codes = list({p.http_status_code for p in flow_packets if p.http_status_code})
    tls_sni_list = list({p.tls_sni for p in flow_packets if p.tls_sni})

    return NetworkFlowRecord(
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        packet_count=len(flow_packets),
        byte_count=total_bytes,
        syn_count=syn_count,
        rst_count=rst_count,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        first_frame_number=flow_packets[0].frame_number,
        last_frame_number=flow_packets[-1].frame_number,
        sample_info_strings=sample_infos,
        http_uris=http_uris,
        http_status_codes=http_status_codes,
        tls_sni_list=tls_sni_list,
    )


def detect_threats_in_traffic(
    packet_records: list[ParsedPacketRecord],
    network_flows: list[NetworkFlowRecord],
) -> list[ThreatAlertRecord]:
    all_alerts: list[ThreatAlertRecord] = []

    all_alerts.extend(_detect_port_scans(packet_records))
    all_alerts.extend(_detect_beaconing_behavior(network_flows))
    all_alerts.extend(_detect_dns_tunneling(packet_records))
    all_alerts.extend(_detect_data_exfiltration(network_flows))
    all_alerts.extend(_detect_brute_force_attempts(network_flows))
    all_alerts.extend(_detect_smb_enumeration(packet_records))
    all_alerts.extend(_detect_lateral_movement(network_flows))

    return all_alerts


def _detect_port_scans(packet_records: list[ParsedPacketRecord]) -> list[ThreatAlertRecord]:
    scan_alerts: list[ThreatAlertRecord] = []

    syn_packets = [p for p in packet_records if p.tcp_flags_syn and not p.tcp_flags_ack]
    ports_by_scanner: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))

    for packet in syn_packets:
        time_bucket = int(packet.timestamp // PORT_SCAN_TIME_WINDOW_SECONDS)
        bucket_key = f"{time_bucket}"
        ports_by_scanner[packet.source_ip][bucket_key].add(packet.destination_port)

    for scanner_ip, time_buckets in ports_by_scanner.items():
        for _bucket_key, scanned_ports in time_buckets.items():
            if len(scanned_ports) >= PORT_SCAN_UNIQUE_PORT_MIN:
                unique_port_count = len(scanned_ports)
                scan_alerts.append(ThreatAlertRecord(
                    alert_id=str(uuid.uuid4())[:8],
                    source_ip=scanner_ip,
                    destination_ip="multiple",
                    threat_category=ThreatCategory.PORT_SCAN,
                    risk_level=RiskLevel.HIGH if unique_port_count > 50 else RiskLevel.MEDIUM,
                    confidence_score=min(0.95, unique_port_count / 100),
                    description=(
                        f"Port scan detected: {scanner_ip} probed {unique_port_count} unique ports "
                        f"within a {PORT_SCAN_TIME_WINDOW_SECONDS}-second window."
                    ),
                    evidence=[f"Unique ports probed: {unique_port_count}",
                              f"Top ports: {sorted(scanned_ports)[:10]}"],
                    mitre_technique_id=MITRE_TECHNIQUE_PORT_SCAN,
                    mitre_technique_name="Network Service Discovery",
                    mitre_tactic_id=MITRE_TACTIC_RECON,
                    mitre_tactic_name="Reconnaissance",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))

    return scan_alerts


def _detect_beaconing_behavior(network_flows: list[NetworkFlowRecord]) -> list[ThreatAlertRecord]:
    beacon_alerts: list[ThreatAlertRecord] = []
    flows_by_source_dest: dict[tuple, list[NetworkFlowRecord]] = defaultdict(list)

    for flow in network_flows:
        if flow.destination_port in {80, 443, 8080, 8443} or flow.destination_port > 1024:
            pair_key = (flow.source_ip, flow.destination_ip, flow.destination_port)
            flows_by_source_dest[pair_key].append(flow)

    for (source_ip, dest_ip, dest_port), pair_flows in flows_by_source_dest.items():
        if len(pair_flows) < BEACONING_MIN_OCCURRENCES:
            continue

        inter_arrival_intervals = _calculate_inter_arrival_intervals(pair_flows)
        if len(inter_arrival_intervals) < BEACONING_MIN_OCCURRENCES - 1:
            continue

        interval_coefficient_of_variation = _calculate_coefficient_of_variation(inter_arrival_intervals)
        if interval_coefficient_of_variation < BEACONING_INTERVAL_VARIANCE_MAX:
            mean_interval = statistics.mean(inter_arrival_intervals)
            beacon_alerts.append(ThreatAlertRecord(
                alert_id=str(uuid.uuid4())[:8],
                source_ip=source_ip,
                destination_ip=dest_ip,
                threat_category=ThreatCategory.BEACONING,
                risk_level=RiskLevel.HIGH,
                confidence_score=min(0.95, 1.0 - interval_coefficient_of_variation),
                description=(
                    f"Beaconing / C2 behavior detected: {source_ip} sends highly periodic "
                    f"traffic to {dest_ip}:{dest_port} every ~{mean_interval:.1f}s "
                    f"(CV={interval_coefficient_of_variation:.3f})."
                ),
                evidence=[
                    f"Connection count: {len(pair_flows)}",
                    f"Mean interval: {mean_interval:.1f}s",
                    f"Interval CV (lower = more periodic): {interval_coefficient_of_variation:.3f}",
                ],
                mitre_technique_id=MITRE_TECHNIQUE_BEACONING,
                mitre_technique_name="Application Layer Protocol",
                mitre_tactic_id=MITRE_TACTIC_C2,
                mitre_tactic_name="Command and Control",
                timestamp=datetime.now(timezone.utc).isoformat(),
            ))

    return beacon_alerts


def _calculate_inter_arrival_intervals(flows: list[NetworkFlowRecord]) -> list[float]:
    sorted_flows = sorted(flows, key=lambda flow: flow.first_seen)
    return [
        sorted_flows[index + 1].first_seen - sorted_flows[index].first_seen
        for index in range(len(sorted_flows) - 1)
        if sorted_flows[index + 1].first_seen > sorted_flows[index].first_seen
    ]


def _calculate_coefficient_of_variation(numeric_values: list[float]) -> float:
    if not numeric_values or len(numeric_values) < 2:
        return 1.0
    mean_value = statistics.mean(numeric_values)
    if mean_value == 0:
        return 1.0
    std_deviation = statistics.pstdev(numeric_values)
    return std_deviation / mean_value


def _detect_dns_tunneling(packet_records: list[ParsedPacketRecord]) -> list[ThreatAlertRecord]:
    dns_alerts: list[ThreatAlertRecord] = []

    dns_packets = [p for p in packet_records if p.dns_query_name]
    dns_queries_by_source: dict[str, list[ParsedPacketRecord]] = defaultdict(list)

    for packet in dns_packets:
        dns_queries_by_source[packet.source_ip].append(packet)

    for source_ip, dns_packets_from_source in dns_queries_by_source.items():
        time_buckets: dict[int, list[ParsedPacketRecord]] = defaultdict(list)
        for packet in dns_packets_from_source:
            bucket_index = int(packet.timestamp // DNS_QUERY_TIME_WINDOW_SECONDS)
            time_buckets[bucket_index].append(packet)

        for _bucket_index, bucket_packets in time_buckets.items():
            if len(bucket_packets) < DNS_QUERY_BURST_MIN:
                continue

            query_names = [p.dns_query_name for p in bucket_packets]
            avg_query_length = sum(len(name) for name in query_names) / len(query_names)

            # Long, high-entropy subdomains indicate DNS tunneling
            long_subdomain_count = sum(1 for name in query_names if _has_long_subdomain(name))
            long_subdomain_ratio = long_subdomain_count / len(query_names)

            if long_subdomain_ratio > 0.3 or avg_query_length > 60:
                dns_alerts.append(ThreatAlertRecord(
                    alert_id=str(uuid.uuid4())[:8],
                    source_ip=source_ip,
                    destination_ip="DNS resolver",
                    threat_category=ThreatCategory.DNS_TUNNELING,
                    risk_level=RiskLevel.HIGH,
                    confidence_score=min(0.90, long_subdomain_ratio + 0.4),
                    description=(
                        f"DNS tunneling suspected: {source_ip} sent {len(bucket_packets)} DNS queries "
                        f"in {DNS_QUERY_TIME_WINDOW_SECONDS}s with avg label length {avg_query_length:.0f} chars."
                    ),
                    evidence=[
                        f"DNS query burst count: {len(bucket_packets)}",
                        f"Average query name length: {avg_query_length:.0f} chars",
                        f"Long-subdomain ratio: {long_subdomain_ratio:.0%}",
                        f"Sample query: {query_names[0][:80]}",
                    ],
                    mitre_technique_id=MITRE_TECHNIQUE_DNS_TUNNEL,
                    mitre_technique_name="DNS Application Layer Protocol",
                    mitre_tactic_id=MITRE_TACTIC_C2,
                    mitre_tactic_name="Command and Control",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))

    return dns_alerts


def _has_long_subdomain(domain_name: str) -> bool:
    min_tunneling_label_length = 25
    labels = domain_name.split(".")
    return any(len(label) >= min_tunneling_label_length for label in labels)


def _detect_data_exfiltration(network_flows: list[NetworkFlowRecord]) -> list[ThreatAlertRecord]:
    exfil_alerts: list[ThreatAlertRecord] = []

    outbound_bytes_by_source: dict[str, int] = defaultdict(int)
    outbound_flows_by_source: dict[str, list[NetworkFlowRecord]] = defaultdict(list)

    private_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "192.168.", "127.")

    for flow in network_flows:
        source_is_internal = any(flow.source_ip.startswith(prefix) for prefix in private_prefixes)
        dest_is_external = not any(flow.destination_ip.startswith(prefix) for prefix in private_prefixes)

        if source_is_internal and dest_is_external:
            outbound_bytes_by_source[flow.source_ip] += flow.byte_count
            outbound_flows_by_source[flow.source_ip].append(flow)

    for source_ip, total_outbound_bytes in outbound_bytes_by_source.items():
        if total_outbound_bytes >= EXFIL_BYTES_THRESHOLD:
            outbound_flow_count = len(outbound_flows_by_source[source_ip])
            megabytes_transferred = total_outbound_bytes / 1_000_000
            exfil_alerts.append(ThreatAlertRecord(
                alert_id=str(uuid.uuid4())[:8],
                source_ip=source_ip,
                destination_ip="external",
                threat_category=ThreatCategory.EXFILTRATION,
                risk_level=RiskLevel.CRITICAL if total_outbound_bytes > EXFIL_BYTES_THRESHOLD * 5 else RiskLevel.HIGH,
                confidence_score=min(0.88, total_outbound_bytes / (EXFIL_BYTES_THRESHOLD * 10)),
                description=(
                    f"Possible data exfiltration: {source_ip} transferred {megabytes_transferred:.1f} MB "
                    f"to external destinations across {outbound_flow_count} flows."
                ),
                evidence=[
                    f"Total outbound bytes: {total_outbound_bytes:,}",
                    f"External flow count: {outbound_flow_count}",
                ],
                mitre_technique_id=MITRE_TECHNIQUE_EXFIL_C2,
                mitre_technique_name="Exfiltration Over C2 Channel",
                mitre_tactic_id=MITRE_TACTIC_EXFILTRATION,
                mitre_tactic_name="Exfiltration",
                timestamp=datetime.now(timezone.utc).isoformat(),
            ))

    return exfil_alerts


def _detect_brute_force_attempts(network_flows: list[NetworkFlowRecord]) -> list[ThreatAlertRecord]:
    brute_force_alerts: list[ThreatAlertRecord] = []

    auth_flows_by_attacker: dict[tuple, list[NetworkFlowRecord]] = defaultdict(list)
    for flow in network_flows:
        if flow.destination_port in REMOTE_ACCESS_PORTS:
            attacker_key = (flow.source_ip, flow.destination_ip, flow.destination_port)
            auth_flows_by_attacker[attacker_key].append(flow)

    for (source_ip, dest_ip, dest_port), auth_flows in auth_flows_by_attacker.items():
        rst_heavy_flows = [f for f in auth_flows if f.rst_count > f.packet_count * 0.3]
        total_connection_attempts = sum(f.syn_count for f in auth_flows)

        if total_connection_attempts >= BRUTE_FORCE_ATTEMPT_MIN and len(rst_heavy_flows) > 2:
            service_name = _port_to_service_name(dest_port)
            brute_force_alerts.append(ThreatAlertRecord(
                alert_id=str(uuid.uuid4())[:8],
                source_ip=source_ip,
                destination_ip=dest_ip,
                threat_category=ThreatCategory.BRUTE_FORCE,
                risk_level=RiskLevel.HIGH,
                confidence_score=min(0.92, total_connection_attempts / (BRUTE_FORCE_ATTEMPT_MIN * 5)),
                description=(
                    f"Brute force attack suspected: {source_ip} made {total_connection_attempts} "
                    f"{service_name} connection attempts to {dest_ip}:{dest_port} "
                    f"with {len(rst_heavy_flows)} reset-heavy flows."
                ),
                evidence=[
                    f"Total SYN attempts: {total_connection_attempts}",
                    f"Reset-heavy flows: {len(rst_heavy_flows)}",
                    f"Target service: {service_name} (port {dest_port})",
                ],
                mitre_technique_id=MITRE_TECHNIQUE_BRUTE_FORCE,
                mitre_technique_name="Brute Force",
                mitre_tactic_id=MITRE_TACTIC_RECON,
                mitre_tactic_name="Credential Access",
                timestamp=datetime.now(timezone.utc).isoformat(),
            ))

    return brute_force_alerts


def _detect_smb_enumeration(packet_records: list[ParsedPacketRecord]) -> list[ThreatAlertRecord]:
    smb_alerts: list[ThreatAlertRecord] = []
    smb_packets_by_source: dict[str, list[ParsedPacketRecord]] = defaultdict(list)

    for packet in packet_records:
        if packet.smb_command or packet.destination_port == 445 or packet.destination_port == 139:
            smb_packets_by_source[packet.source_ip].append(packet)

    for source_ip, smb_packets in smb_packets_by_source.items():
        unique_smb_targets = {p.destination_ip for p in smb_packets}
        if len(smb_packets) >= SMB_ENUM_PACKET_MIN and len(unique_smb_targets) >= 2:
            smb_commands_seen = Counter(p.smb_command for p in smb_packets if p.smb_command)
            smb_alerts.append(ThreatAlertRecord(
                alert_id=str(uuid.uuid4())[:8],
                source_ip=source_ip,
                destination_ip=f"{len(unique_smb_targets)} hosts",
                threat_category=ThreatCategory.SMB_ENUM,
                risk_level=RiskLevel.HIGH,
                confidence_score=min(0.90, len(smb_packets) / 100),
                description=(
                    f"SMB enumeration detected: {source_ip} sent {len(smb_packets)} SMB packets "
                    f"to {len(unique_smb_targets)} unique hosts."
                ),
                evidence=[
                    f"SMB packet count: {len(smb_packets)}",
                    f"Unique SMB targets: {len(unique_smb_targets)}",
                    f"Commands observed: {dict(smb_commands_seen.most_common(3))}",
                ],
                mitre_technique_id=MITRE_TECHNIQUE_SMB_LATERAL,
                mitre_technique_name="SMB/Windows Admin Shares",
                mitre_tactic_id=MITRE_TACTIC_LATERAL_MOVE,
                mitre_tactic_name="Lateral Movement",
                timestamp=datetime.now(timezone.utc).isoformat(),
            ))

    return smb_alerts


def _detect_lateral_movement(network_flows: list[NetworkFlowRecord]) -> list[ThreatAlertRecord]:
    lateral_alerts: list[ThreatAlertRecord] = []
    private_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "192.168.")

    lateral_targets_by_source: dict[str, set[str]] = defaultdict(set)

    for flow in network_flows:
        source_is_internal = any(flow.source_ip.startswith(prefix) for prefix in private_prefixes)
        dest_is_internal = any(flow.destination_ip.startswith(prefix) for prefix in private_prefixes)

        if source_is_internal and dest_is_internal and flow.destination_port in REMOTE_ACCESS_PORTS:
            lateral_targets_by_source[flow.source_ip].add(flow.destination_ip)

    for source_ip, target_hosts in lateral_targets_by_source.items():
        if len(target_hosts) >= LATERAL_MOVEMENT_MIN_HOSTS:
            lateral_alerts.append(ThreatAlertRecord(
                alert_id=str(uuid.uuid4())[:8],
                source_ip=source_ip,
                destination_ip=f"{len(target_hosts)} internal hosts",
                threat_category=ThreatCategory.LATERAL_MOVEMENT,
                risk_level=RiskLevel.CRITICAL,
                confidence_score=min(0.92, len(target_hosts) / 10),
                description=(
                    f"Lateral movement detected: {source_ip} connected to {len(target_hosts)} "
                    f"internal hosts via remote-access protocols (RDP/SSH/SMB/WinRM)."
                ),
                evidence=[
                    f"Unique internal targets: {len(target_hosts)}",
                    f"Target IPs: {sorted(target_hosts)[:5]}",
                ],
                mitre_technique_id=MITRE_TECHNIQUE_SMB_LATERAL,
                mitre_technique_name="Remote Services",
                mitre_tactic_id=MITRE_TACTIC_LATERAL_MOVE,
                mitre_tactic_name="Lateral Movement",
                timestamp=datetime.now(timezone.utc).isoformat(),
            ))

    return lateral_alerts


def _port_to_service_name(port_number: int) -> str:
    port_service_map = {
        21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP",
        5900: "VNC", 5985: "WinRM", 5986: "WinRM-HTTPS",
    }
    return port_service_map.get(port_number, f"port-{port_number}")


def extract_traffic_features_per_host(
    packet_records: list[ParsedPacketRecord],
    network_flows: list[NetworkFlowRecord],
) -> list[dict]:
    from backend.constants import HIGH_RISK_PORTS

    bytes_sent_by_host: dict[str, int] = defaultdict(int)
    bytes_received_by_host: dict[str, int] = defaultdict(int)
    unique_destinations_by_host: dict[str, set] = defaultdict(set)
    unique_ports_contacted_by_host: dict[str, set] = defaultdict(set)
    dns_query_count_by_host: dict[str, int] = defaultdict(int)
    syn_count_by_host: dict[str, int] = defaultdict(int)
    rst_count_by_host: dict[str, int] = defaultdict(int)
    risky_port_contacts_by_host: dict[str, int] = defaultdict(int)

    for flow in network_flows:
        bytes_sent_by_host[flow.source_ip] += flow.byte_count
        bytes_received_by_host[flow.destination_ip] += flow.byte_count
        unique_destinations_by_host[flow.source_ip].add(flow.destination_ip)
        unique_ports_contacted_by_host[flow.source_ip].add(flow.destination_port)
        syn_count_by_host[flow.source_ip] += flow.syn_count
        rst_count_by_host[flow.source_ip] += flow.rst_count
        if flow.destination_port in HIGH_RISK_PORTS:
            risky_port_contacts_by_host[flow.source_ip] += 1

    for packet in packet_records:
        if packet.dns_query_name:
            dns_query_count_by_host[packet.source_ip] += 1

    all_host_ips = set(bytes_sent_by_host) | set(bytes_received_by_host)
    host_feature_list = []

    for host_ip in all_host_ips:
        host_feature_list.append({
            "ip_address": host_ip,
            "bytes_sent": bytes_sent_by_host[host_ip],
            "bytes_received": bytes_received_by_host[host_ip],
            "unique_destination_count": len(unique_destinations_by_host[host_ip]),
            "unique_port_contact_count": len(unique_ports_contacted_by_host[host_ip]),
            "dns_query_count": dns_query_count_by_host[host_ip],
            "syn_packet_count": syn_count_by_host[host_ip],
            "rst_packet_count": rst_count_by_host[host_ip],
            "risky_port_contact_count": risky_port_contacts_by_host[host_ip],
            "outbound_to_inbound_ratio": (
                bytes_sent_by_host[host_ip] / max(bytes_received_by_host[host_ip], 1)
            ),
        })

    return host_feature_list
