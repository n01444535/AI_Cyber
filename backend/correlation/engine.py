import uuid
from collections import defaultdict
from datetime import datetime

from backend.constants import (
    C2_BEACONING_STORY_SCORE,
    CORRELATION_TIME_WINDOW_MINUTES,
    EXFIL_STORY_SCORE,
    LATERAL_MOVEMENT_STORY_SCORE,
    MIN_EVENTS_FOR_STORY,
    MITRE_TACTIC_C2,
    MITRE_TACTIC_EXFILTRATION,
    MITRE_TACTIC_LATERAL_MOVE,
    MITRE_TACTIC_RECON,
    RECON_STORY_SCORE,
)
from backend.models import (
    AttackTimelineEvent,
    CorrelatedAttackStory,
    RiskLevel,
    ThreatAlertRecord,
    ThreatCategory,
)


def correlate_alerts_into_stories(
    threat_alerts: list[ThreatAlertRecord],
) -> list[CorrelatedAttackStory]:
    if len(threat_alerts) < MIN_EVENTS_FOR_STORY:
        return []

    alerts_by_source_ip = _group_alerts_by_source_ip(threat_alerts)
    attack_stories: list[CorrelatedAttackStory] = []

    for source_ip, ip_alerts in alerts_by_source_ip.items():
        stories_for_ip = _detect_attack_patterns_for_ip(source_ip, ip_alerts)
        attack_stories.extend(stories_for_ip)

    cross_ip_stories = _detect_cross_ip_patterns(threat_alerts)
    attack_stories.extend(cross_ip_stories)

    attack_stories.sort(key=lambda story: story.overall_risk_score, reverse=True)
    return attack_stories


def _alerts_span_within_window(alerts: list) -> bool:
    """Return True if all alerts with parseable timestamps fall within the correlation window."""
    timestamps = []
    for alert in alerts:
        if not alert.timestamp:
            continue
        try:
            timestamps.append(datetime.fromisoformat(alert.timestamp).timestamp())
        except ValueError:
            continue
    if len(timestamps) < 2:
        return True
    span_minutes = (max(timestamps) - min(timestamps)) / 60
    return span_minutes <= CORRELATION_TIME_WINDOW_MINUTES


def _group_alerts_by_source_ip(
    threat_alerts: list[ThreatAlertRecord],
) -> dict[str, list[ThreatAlertRecord]]:
    alerts_by_ip: dict[str, list[ThreatAlertRecord]] = defaultdict(list)
    for alert in threat_alerts:
        alerts_by_ip[alert.source_ip].append(alert)
    return dict(alerts_by_ip)


def _detect_attack_patterns_for_ip(
    source_ip: str,
    ip_alerts: list[ThreatAlertRecord],
) -> list[CorrelatedAttackStory]:
    detected_stories: list[CorrelatedAttackStory] = []

    alert_categories = {alert.threat_category for alert in ip_alerts}

    lateral_movement_story = _try_build_lateral_movement_story(
        source_ip, ip_alerts, alert_categories
    )
    if lateral_movement_story:
        detected_stories.append(lateral_movement_story)

    c2_beacon_story = _try_build_c2_beaconing_story(source_ip, ip_alerts, alert_categories)
    if c2_beacon_story:
        detected_stories.append(c2_beacon_story)

    exfiltration_story = _try_build_exfiltration_story(source_ip, ip_alerts, alert_categories)
    if exfiltration_story:
        detected_stories.append(exfiltration_story)

    recon_story = _try_build_reconnaissance_story(source_ip, ip_alerts, alert_categories)
    if recon_story:
        detected_stories.append(recon_story)

    return detected_stories


def _try_build_lateral_movement_story(
    source_ip: str,
    ip_alerts: list[ThreatAlertRecord],
    alert_categories: set[ThreatCategory],
) -> CorrelatedAttackStory | None:
    required_for_lateral = {
        ThreatCategory.PORT_SCAN,
        ThreatCategory.SMB_ENUM,
        ThreatCategory.LATERAL_MOVEMENT,
    }
    has_lateral_signals = bool(required_for_lateral & alert_categories)
    has_brute_force = ThreatCategory.BRUTE_FORCE in alert_categories

    if not has_lateral_signals:
        return None

    supporting_alerts = [
        a
        for a in ip_alerts
        if a.threat_category in required_for_lateral
        or a.threat_category == ThreatCategory.BRUTE_FORCE
    ]

    if not _alerts_span_within_window(supporting_alerts):
        return None

    timeline_events = _build_timeline_events_from_alerts(supporting_alerts)
    all_involved_ips = _collect_all_involved_ips(supporting_alerts)

    narrative = _compose_lateral_movement_narrative(source_ip, alert_categories, has_brute_force)

    return CorrelatedAttackStory(
        story_id=str(uuid.uuid4())[:8],
        involved_ip_addresses=list(all_involved_ips),
        attack_narrative=narrative,
        overall_risk_score=LATERAL_MOVEMENT_STORY_SCORE,
        risk_level=RiskLevel.CRITICAL,
        timeline_events=timeline_events,
        mitre_tactics=[MITRE_TACTIC_RECON, MITRE_TACTIC_LATERAL_MOVE],
        mitre_techniques=list(
            {a.mitre_technique_id for a in supporting_alerts if a.mitre_technique_id}
        ),
        supporting_alert_ids=[a.alert_id for a in supporting_alerts],
        ai_explanation=narrative,
        first_seen=min((a.timestamp for a in supporting_alerts if a.timestamp), default=""),
        last_seen=max((a.timestamp for a in supporting_alerts if a.timestamp), default=""),
    )


def _try_build_c2_beaconing_story(
    source_ip: str,
    ip_alerts: list[ThreatAlertRecord],
    alert_categories: set[ThreatCategory],
) -> CorrelatedAttackStory | None:
    has_beaconing = ThreatCategory.BEACONING in alert_categories

    if not has_beaconing:
        return None

    supporting_alerts = [
        a
        for a in ip_alerts
        if a.threat_category in {ThreatCategory.BEACONING, ThreatCategory.SUSPICIOUS_OUTBOUND}
    ]

    if not _alerts_span_within_window(supporting_alerts):
        return None

    timeline_events = _build_timeline_events_from_alerts(supporting_alerts)
    all_involved_ips = _collect_all_involved_ips(supporting_alerts)

    narrative = (
        f"{source_ip} exhibits highly periodic outbound encrypted traffic consistent with "
        f"command-and-control (C2) beaconing behavior. "
        f"The host sends regular callbacks to external destinations at near-constant intervals, "
        f"suggesting a remote access tool or malware implant is active. "
        f"Immediate isolation and memory forensics are recommended."
    )

    return CorrelatedAttackStory(
        story_id=str(uuid.uuid4())[:8],
        involved_ip_addresses=list(all_involved_ips),
        attack_narrative=narrative,
        overall_risk_score=C2_BEACONING_STORY_SCORE,
        risk_level=RiskLevel.CRITICAL,
        timeline_events=timeline_events,
        mitre_tactics=[MITRE_TACTIC_C2],
        mitre_techniques=list(
            {a.mitre_technique_id for a in supporting_alerts if a.mitre_technique_id}
        ),
        supporting_alert_ids=[a.alert_id for a in supporting_alerts],
        ai_explanation=narrative,
        first_seen=min((a.timestamp for a in supporting_alerts if a.timestamp), default=""),
        last_seen=max((a.timestamp for a in supporting_alerts if a.timestamp), default=""),
    )


def _try_build_exfiltration_story(
    source_ip: str,
    ip_alerts: list[ThreatAlertRecord],
    alert_categories: set[ThreatCategory],
) -> CorrelatedAttackStory | None:
    has_exfil = ThreatCategory.EXFILTRATION in alert_categories
    has_beaconing = ThreatCategory.BEACONING in alert_categories
    has_dns_tunnel = ThreatCategory.DNS_TUNNELING in alert_categories

    if not has_exfil and not (has_dns_tunnel and has_beaconing):
        return None

    supporting_alerts = [
        a
        for a in ip_alerts
        if a.threat_category
        in {
            ThreatCategory.EXFILTRATION,
            ThreatCategory.DNS_TUNNELING,
            ThreatCategory.BEACONING,
        }
    ]

    if not _alerts_span_within_window(supporting_alerts):
        return None

    channels_used = []
    if has_exfil:
        channels_used.append("large outbound data transfer")
    if has_dns_tunnel:
        channels_used.append("DNS tunneling")
    if has_beaconing:
        channels_used.append("periodic beaconing channel")

    channels_string = " and ".join(channels_used)
    narrative = (
        f"{source_ip} shows strong indicators of data exfiltration via {channels_string}. "
        f"Sensitive data may have been staged and transmitted to an attacker-controlled server. "
        f"Network forensics and DLP review are urgently recommended."
    )

    all_involved_ips = _collect_all_involved_ips(supporting_alerts)
    timeline_events = _build_timeline_events_from_alerts(supporting_alerts)

    return CorrelatedAttackStory(
        story_id=str(uuid.uuid4())[:8],
        involved_ip_addresses=list(all_involved_ips),
        attack_narrative=narrative,
        overall_risk_score=EXFIL_STORY_SCORE,
        risk_level=RiskLevel.CRITICAL,
        timeline_events=timeline_events,
        mitre_tactics=[MITRE_TACTIC_EXFILTRATION, MITRE_TACTIC_C2],
        mitre_techniques=list(
            {a.mitre_technique_id for a in supporting_alerts if a.mitre_technique_id}
        ),
        supporting_alert_ids=[a.alert_id for a in supporting_alerts],
        ai_explanation=narrative,
        first_seen=min((a.timestamp for a in supporting_alerts if a.timestamp), default=""),
        last_seen=max((a.timestamp for a in supporting_alerts if a.timestamp), default=""),
    )


def _try_build_reconnaissance_story(
    source_ip: str,
    ip_alerts: list[ThreatAlertRecord],
    alert_categories: set[ThreatCategory],
) -> CorrelatedAttackStory | None:
    recon_signals = {ThreatCategory.PORT_SCAN, ThreatCategory.RECON}
    recon_count = len(recon_signals & alert_categories)

    if recon_count < 1:
        return None

    if len(ip_alerts) < 2:
        return None

    supporting_alerts = [a for a in ip_alerts if a.threat_category in recon_signals]

    if not _alerts_span_within_window(supporting_alerts):
        return None

    narrative = (
        f"{source_ip} is conducting active network reconnaissance. "
        f"Port scanning and service discovery activity suggest the attacker is mapping the "
        f"network attack surface prior to exploitation. "
        f"Monitor for follow-on exploitation activity."
    )

    all_involved_ips = _collect_all_involved_ips(supporting_alerts)
    timeline_events = _build_timeline_events_from_alerts(supporting_alerts)

    return CorrelatedAttackStory(
        story_id=str(uuid.uuid4())[:8],
        involved_ip_addresses=list(all_involved_ips),
        attack_narrative=narrative,
        overall_risk_score=RECON_STORY_SCORE,
        risk_level=RiskLevel.HIGH,
        timeline_events=timeline_events,
        mitre_tactics=[MITRE_TACTIC_RECON],
        mitre_techniques=list(
            {a.mitre_technique_id for a in supporting_alerts if a.mitre_technique_id}
        ),
        supporting_alert_ids=[a.alert_id for a in supporting_alerts],
        ai_explanation=narrative,
        first_seen=min((a.timestamp for a in supporting_alerts if a.timestamp), default=""),
        last_seen=max((a.timestamp for a in supporting_alerts if a.timestamp), default=""),
    )


def _detect_cross_ip_patterns(
    threat_alerts: list[ThreatAlertRecord],
) -> list[CorrelatedAttackStory]:
    cross_stories: list[CorrelatedAttackStory] = []

    scan_alerts = [a for a in threat_alerts if a.threat_category == ThreatCategory.PORT_SCAN]
    lateral_alerts = [
        a for a in threat_alerts if a.threat_category == ThreatCategory.LATERAL_MOVEMENT
    ]
    exfil_alerts = [a for a in threat_alerts if a.threat_category == ThreatCategory.EXFILTRATION]
    beacon_alerts = [a for a in threat_alerts if a.threat_category == ThreatCategory.BEACONING]

    if scan_alerts and lateral_alerts and (exfil_alerts or beacon_alerts):
        all_involved_ips = list(
            {a.source_ip for a in scan_alerts + lateral_alerts + exfil_alerts + beacon_alerts}
        )
        supporting_alerts = scan_alerts + lateral_alerts + exfil_alerts + beacon_alerts
        timeline_events = _build_timeline_events_from_alerts(supporting_alerts)

        narrative = (
            f"Full attack chain detected across {len(all_involved_ips)} hosts: "
            f"Reconnaissance (port scanning) → Lateral Movement (SMB/RDP/SSH) → "
            f"{'Data Exfiltration' if exfil_alerts else 'C2 Beaconing'}. "
            f"This pattern is consistent with an Advanced Persistent Threat (APT) campaign. "
            f"Immediate incident response is required."
        )

        cross_stories.append(
            CorrelatedAttackStory(
                story_id=str(uuid.uuid4())[:8],
                involved_ip_addresses=all_involved_ips,
                attack_narrative=narrative,
                overall_risk_score=95.0,
                risk_level=RiskLevel.CRITICAL,
                timeline_events=timeline_events,
                mitre_tactics=[
                    MITRE_TACTIC_RECON,
                    MITRE_TACTIC_LATERAL_MOVE,
                    MITRE_TACTIC_EXFILTRATION,
                    MITRE_TACTIC_C2,
                ],
                mitre_techniques=list(
                    {a.mitre_technique_id for a in supporting_alerts if a.mitre_technique_id}
                ),
                supporting_alert_ids=[a.alert_id for a in supporting_alerts],
                ai_explanation=narrative,
                first_seen=min((a.timestamp for a in supporting_alerts if a.timestamp), default=""),
                last_seen=max((a.timestamp for a in supporting_alerts if a.timestamp), default=""),
            )
        )

    return cross_stories


def _build_timeline_events_from_alerts(
    alerts: list[ThreatAlertRecord],
) -> list[AttackTimelineEvent]:
    sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)
    return [
        AttackTimelineEvent(
            event_time=alert.timestamp,
            source_ip=alert.source_ip,
            destination_ip=alert.destination_ip,
            event_description=alert.description,
            threat_category=alert.threat_category,
            mitre_technique_id=alert.mitre_technique_id,
            mitre_tactic_name=alert.mitre_tactic_name,
            risk_level=alert.risk_level,
            related_alert_id=alert.alert_id,
        )
        for alert in sorted_alerts
    ]


def _collect_all_involved_ips(alerts: list[ThreatAlertRecord]) -> set[str]:
    all_ips: set[str] = set()
    for alert in alerts:
        all_ips.add(alert.source_ip)
        if alert.destination_ip not in {"multiple", "external", "DNS resolver"}:
            if not alert.destination_ip.endswith("hosts"):
                all_ips.add(alert.destination_ip)
    return all_ips


def _compose_lateral_movement_narrative(
    source_ip: str,
    alert_categories: set[ThreatCategory],
    has_brute_force: bool,
) -> str:
    technique_descriptions = []
    if ThreatCategory.PORT_SCAN in alert_categories:
        technique_descriptions.append("active port scanning to map network services")
    if ThreatCategory.SMB_ENUM in alert_categories:
        technique_descriptions.append(
            "SMB enumeration to discover shared resources and user accounts"
        )
    if ThreatCategory.BRUTE_FORCE in alert_categories:
        technique_descriptions.append(
            "brute-force credential attacks against remote access services"
        )
    if ThreatCategory.LATERAL_MOVEMENT in alert_categories:
        technique_descriptions.append(
            "lateral movement to multiple internal hosts via remote protocols"
        )

    techniques_string = ", ".join(technique_descriptions)
    return (
        f"{source_ip} shows a coordinated lateral movement attack chain: {techniques_string}. "
        f"This host has systematically probed, enumerated, and traversed the internal network. "
        f"The behavior is consistent with a post-compromise attacker establishing persistence "
        f"and expanding access across multiple systems. "
        f"Isolate this host immediately and conduct forensic investigation."
    )
