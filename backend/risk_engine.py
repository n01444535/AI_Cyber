from backend.constants import (
    CRITICAL_RISK_PORTS,
    HIGH_RISK_PORTS,
    RISK_SCORE_CRITICAL_MIN,
    RISK_SCORE_HIGH_MIN,
    RISK_SCORE_MEDIUM_MIN,
    RISK_WEIGHT_CORRELATION,
    RISK_WEIGHT_ML_ANOMALY,
    RISK_WEIGHT_OPEN_PORTS,
    RISK_WEIGHT_THREAT_INTEL,
    RISK_WEIGHT_TRAFFIC,
)
from backend.models import (
    AnomalyDetectionResult,
    CorrelatedAttackStory,
    HostRiskProfile,
    IOCLookupResult,
    RiskLevel,
    ScannedHostRecord,
    ThreatAlertRecord,
    ThreatCategory,
)


def calculate_host_risk_profiles(
    scanned_hosts: list[ScannedHostRecord],
    threat_alerts: list[ThreatAlertRecord],
    anomaly_results: list[AnomalyDetectionResult],
    ioc_results: list[IOCLookupResult],
    attack_stories: list[CorrelatedAttackStory],
) -> list[HostRiskProfile]:
    alerts_by_ip = _group_alerts_by_ip(threat_alerts)
    anomaly_by_ip = {result.ip_address: result for result in anomaly_results}
    ioc_by_ip = {result.indicator: result for result in ioc_results}
    story_score_by_ip = _build_story_score_by_ip(attack_stories)

    host_risk_profiles: list[HostRiskProfile] = []

    all_host_ips = {host.ip_address for host in scanned_hosts}
    all_alert_ips = {alert.source_ip for alert in threat_alerts}
    all_host_ips.update(all_alert_ips)

    host_records_by_ip = {host.ip_address: host for host in scanned_hosts}

    for host_ip in all_host_ips:
        host_record = host_records_by_ip.get(host_ip)
        host_alerts = alerts_by_ip.get(host_ip, [])
        anomaly_result = anomaly_by_ip.get(host_ip)
        ioc_result = ioc_by_ip.get(host_ip)
        correlation_score = story_score_by_ip.get(host_ip, 0.0)

        port_risk_score = _calculate_port_risk_score(host_record) if host_record else 0.0
        threat_intel_score = _calculate_threat_intel_score(ioc_result)
        anomaly_score_value = anomaly_result.anomaly_score if anomaly_result else 0.0
        traffic_behavior_score = _calculate_traffic_behavior_score(host_alerts)

        weighted_risk_score = (
            (port_risk_score * RISK_WEIGHT_OPEN_PORTS / 100)
            + (threat_intel_score * RISK_WEIGHT_THREAT_INTEL / 100)
            + (anomaly_score_value * 100 * RISK_WEIGHT_ML_ANOMALY / 100)
            + (traffic_behavior_score * RISK_WEIGHT_TRAFFIC / 100)
            + (correlation_score * RISK_WEIGHT_CORRELATION / 100)
        )

        final_risk_score = min(100.0, round(weighted_risk_score, 1))
        risk_level = _score_to_risk_level(final_risk_score)

        open_port_count = len(host_record.open_ports) if host_record else 0
        critical_port_count = (
            len([p for p in host_record.open_ports if p.port_number in CRITICAL_RISK_PORTS])
            if host_record
            else 0
        )

        ai_explanation = _compose_ai_explanation(
            host_ip=host_ip,
            host_record=host_record,
            host_alerts=host_alerts,
            anomaly_result=anomaly_result,
            ioc_result=ioc_result,
            risk_level=risk_level,
        )

        mitre_techniques = list(
            {alert.mitre_technique_id for alert in host_alerts if alert.mitre_technique_id}
        )

        correlated_story_narrative = ""
        for story in attack_stories:
            if host_ip in story.involved_ip_addresses:
                correlated_story_narrative = story.attack_narrative
                break

        host_risk_profiles.append(
            HostRiskProfile(
                ip_address=host_ip,
                hostname=host_record.hostname if host_record else "",
                risk_score=final_risk_score,
                risk_level=risk_level,
                open_port_count=open_port_count,
                critical_port_count=critical_port_count,
                anomaly_score=anomaly_score_value,
                is_ml_anomaly=anomaly_result.is_anomaly if anomaly_result else False,
                threat_alerts=host_alerts,
                ioc_results=[ioc_result] if ioc_result else [],
                ai_explanation=ai_explanation,
                mitre_techniques=mitre_techniques,
                correlated_story=correlated_story_narrative,
            )
        )

    host_risk_profiles.sort(key=lambda profile: profile.risk_score, reverse=True)
    return host_risk_profiles


def _calculate_port_risk_score(host_record: ScannedHostRecord) -> float:
    if not host_record or not host_record.open_ports:
        return 0.0

    open_port_numbers = {port.port_number for port in host_record.open_ports}
    critical_count = len(open_port_numbers & CRITICAL_RISK_PORTS)
    high_risk_count = len(open_port_numbers & HIGH_RISK_PORTS)
    total_open = len(open_port_numbers)

    critical_weight = 20
    high_weight = 8
    open_port_weight = 2

    raw_score = (
        (critical_count * critical_weight)
        + (high_risk_count * high_weight)
        + (total_open * open_port_weight)
    )
    return min(100.0, float(raw_score))


def _calculate_threat_intel_score(ioc_result: IOCLookupResult | None) -> float:
    if not ioc_result:
        return 0.0
    if ioc_result.is_malicious:
        base_score = 80.0
        vt_bonus = min(20.0, ioc_result.virustotal_positives * 2)
        return min(100.0, base_score + vt_bonus)
    abuse_score = min(50.0, ioc_result.abuseipdb_confidence_score)
    otx_score = min(20.0, ioc_result.otx_pulse_count * 5)
    return abuse_score + otx_score


def _calculate_traffic_behavior_score(host_alerts: list[ThreatAlertRecord]) -> float:
    if not host_alerts:
        return 0.0

    category_score_map = {
        ThreatCategory.BEACONING: 90,
        ThreatCategory.EXFILTRATION: 85,
        ThreatCategory.LATERAL_MOVEMENT: 85,
        ThreatCategory.DNS_TUNNELING: 75,
        ThreatCategory.SMB_ENUM: 70,
        ThreatCategory.BRUTE_FORCE: 65,
        ThreatCategory.PORT_SCAN: 50,
        ThreatCategory.KNOWN_MALICIOUS: 80,
        ThreatCategory.SUSPICIOUS_OUTBOUND: 55,
        ThreatCategory.RECON: 45,
        ThreatCategory.ANOMALY: 40,
    }

    max_category_score = max(
        category_score_map.get(alert.threat_category, 0) * alert.confidence_score
        for alert in host_alerts
    )
    return min(100.0, float(max_category_score))


def _build_story_score_by_ip(attack_stories: list[CorrelatedAttackStory]) -> dict[str, float]:
    story_scores: dict[str, float] = {}
    for story in attack_stories:
        for ip_address in story.involved_ip_addresses:
            existing_score = story_scores.get(ip_address, 0.0)
            story_scores[ip_address] = max(existing_score, story.overall_risk_score)
    return story_scores


def _score_to_risk_level(risk_score: float) -> RiskLevel:
    if risk_score >= RISK_SCORE_CRITICAL_MIN:
        return RiskLevel.CRITICAL
    if risk_score >= RISK_SCORE_HIGH_MIN:
        return RiskLevel.HIGH
    if risk_score >= RISK_SCORE_MEDIUM_MIN:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _compose_ai_explanation(
    host_ip: str,
    host_record: ScannedHostRecord | None,
    host_alerts: list[ThreatAlertRecord],
    anomaly_result: AnomalyDetectionResult | None,
    ioc_result: IOCLookupResult | None,
    risk_level: RiskLevel,
) -> str:
    explanation_parts: list[str] = []

    if host_record and host_record.open_ports:
        open_port_numbers = [p.port_number for p in host_record.open_ports]
        critical_ports_found = [p for p in open_port_numbers if p in CRITICAL_RISK_PORTS]
        if critical_ports_found:
            explanation_parts.append(
                f"Host exposes {len(critical_ports_found)} critical service(s) "
                f"(ports {critical_ports_found[:5]}) that are common attack vectors."
            )

    if ioc_result and ioc_result.is_malicious:
        explanation_parts.append(
            f"IP address flagged as malicious by threat intelligence: "
            f"VirusTotal {ioc_result.virustotal_positives}/{ioc_result.virustotal_total_scanners} detections, "
            f"AbuseIPDB confidence {ioc_result.abuseipdb_confidence_score}%."
        )

    alert_category_names = [alert.threat_category.value for alert in host_alerts]
    if alert_category_names:
        unique_categories = list(dict.fromkeys(alert_category_names))
        explanation_parts.append(f"Behavioral detections: {', '.join(unique_categories[:5])}.")

    if anomaly_result and anomaly_result.is_anomaly:
        contributing = ", ".join(anomaly_result.contributing_features[:3])
        explanation_parts.append(
            f"ML anomaly detected (score={anomaly_result.anomaly_score:.2f})"
            + (f" — elevated in: {contributing}." if contributing else ".")
        )

    if not explanation_parts:
        return f"Host {host_ip} shows low-risk profile with no significant indicators."

    risk_label_string = risk_level.value.upper()
    summary = f"[{risk_label_string}] {host_ip}: " + " ".join(explanation_parts)
    return summary


def _group_alerts_by_ip(
    threat_alerts: list[ThreatAlertRecord],
) -> dict[str, list[ThreatAlertRecord]]:
    alerts_by_ip: dict[str, list[ThreatAlertRecord]] = {}
    for alert in threat_alerts:
        if alert.source_ip not in alerts_by_ip:
            alerts_by_ip[alert.source_ip] = []
        alerts_by_ip[alert.source_ip].append(alert)
    return alerts_by_ip
