"""
Per-category analyst guidance: possible false positive explanations
and recommended next steps for each threat category.
"""

from backend.models import ThreatCategory

_GUIDANCE: dict[ThreatCategory, dict[str, list[str]]] = {
    ThreatCategory.PORT_SCAN: {
        "possible_false_positive": [
            "Authorized vulnerability scanner (Nessus, OpenVAS, Qualys)",
            "IT asset inventory or discovery tool",
            "Approved penetration test in progress",
            "Network monitoring agent performing connectivity checks",
        ],
        "recommended_actions": [
            "Verify whether the source IP is an approved scanner or IT asset",
            "Check firewall and IDS logs for correlated connection attempts",
            "Review authentication logs for follow-up login attempts",
            "Monitor for subsequent exploitation activity from the same source",
            "Block the source IP if unauthorized scanning is confirmed",
        ],
    },
    ThreatCategory.BEACONING: {
        "possible_false_positive": [
            "Legitimate software update or telemetry service",
            "IT monitoring agent or heartbeat mechanism",
            "Browser sync or cloud backup tool",
            "Scheduled business application polling",
        ],
        "recommended_actions": [
            "Check reputation of the destination IP/domain (VirusTotal, AbuseIPDB)",
            "Inspect the process on the endpoint making the outbound connections",
            "Look for unusual or obfuscated user-agent strings",
            "Review endpoint process tree for injected or unexpected processes",
            "Block the external destination if confirmed malicious",
        ],
    },
    ThreatCategory.SMB_ENUM: {
        "possible_false_positive": [
            "Authorized vulnerability scanner targeting SMB shares",
            "IT admin workstation accessing multiple file shares",
            "Scheduled configuration audit or compliance scan",
            "Domain controller performing replication checks",
        ],
        "recommended_actions": [
            "Verify source host ownership and role (workstation, scanner, server)",
            "Check Windows Security event logs for failed/successful share access",
            "Review endpoint process activity for unusual tools (enum4linux, smbclient)",
            "Disable SMB on hosts that do not require it",
            "Isolate source host if unauthorized SMB enumeration is confirmed",
        ],
    },
    ThreatCategory.BRUTE_FORCE: {
        "possible_false_positive": [
            "Password manager retrying cached credentials",
            "SSO/SAML misconfiguration causing repeated authentication failures",
            "Expired service account credentials triggering auto-retry",
            "User lockout during routine password rotation",
        ],
        "recommended_actions": [
            "Temporarily lock the targeted account(s) and alert the account owner",
            "Check for successful logins immediately following the failure spike",
            "Enable MFA on the targeted service if not already active",
            "Review authentication logs for source IP and user agent",
            "Block the source IP at the firewall if external brute force is confirmed",
        ],
    },
    ThreatCategory.DNS_TUNNELING: {
        "possible_false_positive": [
            "Legitimate DNS-based CDN or load balancer generating long subdomains",
            "DNS-over-HTTPS fallback generating unusual query patterns",
            "Domain Generation Algorithm (DGA) detection false positive on legitimate software",
            "Internal DNS resolver creating large query bursts during cache flush",
        ],
        "recommended_actions": [
            "Inspect DNS query content for encoded or unusually long subdomain strings",
            "Check the queried domain against threat intelligence feeds",
            "Block unauthorized external DNS resolvers; enforce internal DNS only",
            "Review the process on the endpoint generating DNS queries",
            "Look for correlated data exfiltration or beaconing activity",
        ],
    },
    ThreatCategory.EXFILTRATION: {
        "possible_false_positive": [
            "Approved cloud backup or file synchronization service",
            "Authorized large software or patch download",
            "Legitimate bulk data transfer to a known business partner",
            "Database replication or disaster recovery traffic",
        ],
        "recommended_actions": [
            "Identify the destination IP/domain and volume of data transferred",
            "Verify whether the transfer was approved by the data owner",
            "Check DLP logs and email security for correlated data leakage",
            "Review the process and user account initiating the transfer",
            "Isolate the source host if unauthorized exfiltration is confirmed",
        ],
    },
    ThreatCategory.LATERAL_MOVEMENT: {
        "possible_false_positive": [
            "Authorized IT helpdesk performing remote administration",
            "Automated deployment or configuration management tool (Ansible, SCCM)",
            "Domain controller authenticating to multiple workstations",
            "Legitimate privileged user performing multi-host maintenance",
        ],
        "recommended_actions": [
            "Verify the source host role and whether multi-host access is expected",
            "Check authentication logs on all target hosts for the same account",
            "Look for privilege escalation attempts alongside the lateral movement",
            "Review Windows event IDs 4624, 4648, 4688 on the source host",
            "Isolate source host if unauthorized lateral movement is confirmed",
        ],
    },
    ThreatCategory.SUSPICIOUS_OUTBOUND: {
        "possible_false_positive": [
            "Authorized cloud service or SaaS platform endpoint",
            "Software automatic update or license check",
            "Legitimate CDN edge node with an unusual IP reputation",
            "Developer API call to an external service",
        ],
        "recommended_actions": [
            "Check destination IP/domain reputation in threat intel feeds",
            "Identify the process making the outbound connection on the endpoint",
            "Look for unusual user agent strings or encrypted payload anomalies",
            "Monitor data volume to detect potential exfiltration",
            "Block the destination if reputation check confirms malicious activity",
        ],
    },
    ThreatCategory.KNOWN_MALICIOUS: {
        "possible_false_positive": [
            "Shared hosting or CDN IP incorrectly flagged in threat intel feed",
            "Threat intel feed false positive — verify with a second source",
            "Previously malicious IP that has since been cleaned and reassigned",
        ],
        "recommended_actions": [
            "Immediately block the malicious IP/domain at the perimeter firewall",
            "Investigate all connections to and from this indicator across the environment",
            "Scan the source host for malware indicators (hash check, AV scan)",
            "Check for persistence mechanisms (startup entries, scheduled tasks)",
            "Report the indicator to your threat intel sharing platform",
        ],
    },
    ThreatCategory.RECON: {
        "possible_false_positive": [
            "Authorized red team or penetration test",
            "Automated asset discovery by IT operations",
            "Network mapping tool run by an approved administrator",
        ],
        "recommended_actions": [
            "Verify whether a penetration test or red team exercise is scheduled",
            "Check firewall logs for the full scope of reconnaissance activity",
            "Monitor the source IP for escalation to exploitation attempts",
            "Tighten network segmentation to reduce discoverable attack surface",
        ],
    },
    ThreatCategory.ANOMALY: {
        "possible_false_positive": [
            "New host added to the network with an unusual service profile",
            "One-off batch job or maintenance task generating atypical traffic",
            "Seasonal traffic spike from a legitimate business process",
        ],
        "recommended_actions": [
            "Correlate the anomaly with other alerts from the same source",
            "Review endpoint activity logs for the flagged host",
            "Check whether the behavior is consistent with the host's expected role",
            "Add the host to a watchlist for continued monitoring",
        ],
    },
}

_DEFAULT_FALSE_POSITIVES = ["Legitimate administrative activity", "Authorized security tool"]
_DEFAULT_ACTIONS = [
    "Investigate the source host and associated user account",
    "Review related network and endpoint logs",
    "Escalate to Tier 2 analyst if behavior cannot be explained",
]


def get_false_positive_explanations(category: ThreatCategory) -> list[str]:
    return _GUIDANCE.get(category, {}).get("possible_false_positive", _DEFAULT_FALSE_POSITIVES)


def get_recommended_actions(category: ThreatCategory) -> list[str]:
    return _GUIDANCE.get(category, {}).get("recommended_actions", _DEFAULT_ACTIONS)
