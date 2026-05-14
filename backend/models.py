from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskLevel(str, Enum):
    LOW      = "Low"
    MEDIUM   = "Medium"
    HIGH     = "High"
    CRITICAL = "Critical"


class ThreatCategory(str, Enum):
    PORT_SCAN        = "Port Scan"
    BRUTE_FORCE      = "Brute Force"
    LATERAL_MOVEMENT = "Lateral Movement"
    BEACONING        = "Beaconing / C2"
    DNS_TUNNELING    = "DNS Tunneling"
    EXFILTRATION     = "Data Exfiltration"
    SMB_ENUM         = "SMB Enumeration"
    RECON            = "Reconnaissance"
    ANOMALY          = "ML Anomaly"
    SUSPICIOUS_OUTBOUND = "Suspicious Outbound"
    KNOWN_MALICIOUS  = "Known Malicious IP/Domain"


# ── Nmap scan models ───────────────────────────────────────────────────────────

@dataclass
class PortRecord:
    port_number: int
    protocol: str
    state: str
    service_name: str
    product: str = ""
    version: str = ""
    extra_info: str = ""
    tunnel: str = ""
    script_outputs: list[dict] = field(default_factory=list)


@dataclass
class ScannedHostRecord:
    ip_address: str
    hostname: str
    operating_system: str
    mac_address: str
    mac_vendor: str
    open_ports: list[PortRecord] = field(default_factory=list)
    raw_nmap_status: str = "up"
    scan_timestamp: str = ""


# ── Packet / traffic models ────────────────────────────────────────────────────

@dataclass(frozen=True)
class ParsedPacketRecord:
    timestamp: float
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    packet_length: int
    tcp_flags_syn: int
    tcp_flags_ack: int
    tcp_flags_rst: int
    tcp_flags_fin: int
    tcp_flags_psh: int
    tcp_flags_urg: int
    hop_limit: int
    frame_number: int = 0
    info_string: str = ""
    http_method: str = ""
    http_uri: str = ""
    http_status_code: str = ""
    http_user_agent: str = ""
    dns_query_name: str = ""
    dns_response_code: str = ""
    is_dns_ptr_query: int = 0
    arp_opcode: int = 0
    source_mac: str = ""
    arp_target_ip: str = ""
    smb_command: str = ""
    tls_sni: str = ""


@dataclass
class NetworkFlowRecord:
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    packet_count: int
    byte_count: int
    syn_count: int
    rst_count: int
    first_seen: float
    last_seen: float
    duration_seconds: float
    risk_score: float = 0.0
    first_frame_number: int = 0
    last_frame_number: int = 0
    sample_info_strings: list[str] = field(default_factory=list)
    http_uris: list[str] = field(default_factory=list)
    http_status_codes: list[str] = field(default_factory=list)
    tls_sni_list: list[str] = field(default_factory=list)


# ── Threat / alert models ──────────────────────────────────────────────────────

@dataclass
class ThreatAlertRecord:
    alert_id: str
    source_ip: str
    destination_ip: str
    threat_category: ThreatCategory
    risk_level: RiskLevel
    confidence_score: float
    description: str
    evidence: list[str] = field(default_factory=list)
    mitre_technique_id: str = ""
    mitre_technique_name: str = ""
    mitre_tactic_id: str = ""
    mitre_tactic_name: str = ""
    timestamp: str = ""
    raw_event_ids: list[str] = field(default_factory=list)


@dataclass
class AttackTimelineEvent:
    event_time: str
    source_ip: str
    destination_ip: str
    event_description: str
    threat_category: ThreatCategory
    mitre_technique_id: str = ""
    mitre_tactic_name: str = ""
    risk_level: RiskLevel = RiskLevel.MEDIUM
    related_alert_id: str = ""


# ── Host risk models ───────────────────────────────────────────────────────────

@dataclass
class IOCLookupResult:
    indicator: str
    indicator_type: str
    is_malicious: bool
    virustotal_positives: int = 0
    virustotal_total_scanners: int = 0
    abuseipdb_confidence_score: int = 0
    otx_pulse_count: int = 0
    last_analysis_timestamp: str = ""
    error_message: str = ""


@dataclass
class HostRiskProfile:
    ip_address: str
    hostname: str
    risk_score: float
    risk_level: RiskLevel
    open_port_count: int
    critical_port_count: int
    anomaly_score: float
    is_ml_anomaly: bool
    threat_alerts: list[ThreatAlertRecord] = field(default_factory=list)
    ioc_results: list[IOCLookupResult] = field(default_factory=list)
    ai_explanation: str = ""
    mitre_techniques: list[str] = field(default_factory=list)
    correlated_story: str = ""


# ── Correlation model ──────────────────────────────────────────────────────────

@dataclass
class CorrelatedAttackStory:
    story_id: str
    involved_ip_addresses: list[str]
    attack_narrative: str
    overall_risk_score: float
    risk_level: RiskLevel
    timeline_events: list[AttackTimelineEvent] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    supporting_alert_ids: list[str] = field(default_factory=list)
    ai_explanation: str = ""
    first_seen: str = ""
    last_seen: str = ""


# ── ML model output ────────────────────────────────────────────────────────────

@dataclass
class AnomalyDetectionResult:
    ip_address: str
    anomaly_score: float
    is_anomaly: bool
    contributing_features: list[str] = field(default_factory=list)


@dataclass
class TrafficClusterRecord:
    cluster_id: int
    member_ips: list[str]
    centroid_features: dict = field(default_factory=dict)
    cluster_label: str = ""
    is_noise: bool = False


# ── Scan session model ─────────────────────────────────────────────────────────

@dataclass
class ScanSessionResult:
    session_id: str
    scan_timestamp: str
    scanned_hosts: list[ScannedHostRecord] = field(default_factory=list)
    threat_alerts: list[ThreatAlertRecord] = field(default_factory=list)
    host_risk_profiles: list[HostRiskProfile] = field(default_factory=list)
    attack_stories: list[CorrelatedAttackStory] = field(default_factory=list)
    timeline_events: list[AttackTimelineEvent] = field(default_factory=list)
    total_risk_score: float = 0.0
    executive_summary: str = ""
    pcap_file_path: Optional[str] = None
    nmap_file_path: Optional[str] = None
