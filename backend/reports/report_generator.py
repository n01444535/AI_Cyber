import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from backend.models import (
    CorrelatedAttackStory,
    HostRiskProfile,
    RiskLevel,
    ScanSessionResult,
    ThreatAlertRecord,
)


RISK_LEVEL_PRIORITY = {
    RiskLevel.CRITICAL: 0,
    RiskLevel.HIGH:     1,
    RiskLevel.MEDIUM:   2,
    RiskLevel.LOW:      3,
}


def generate_report(session_result: ScanSessionResult, output_directory: str) -> dict[str, str]:
    Path(output_directory).mkdir(parents=True, exist_ok=True)
    timestamp_string = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base_filename = f"cyber_report_{timestamp_string}"

    json_file_path = os.path.join(output_directory, f"{base_filename}.json")
    html_file_path = os.path.join(output_directory, f"{base_filename}.html")

    report_data = _build_report_data_dict(session_result)

    with open(json_file_path, "w", encoding="utf-8") as json_file:
        json.dump(report_data, json_file, indent=2, ensure_ascii=False, default=str)

    html_content = _render_html_report(report_data, session_result)
    with open(html_file_path, "w", encoding="utf-8") as html_file:
        html_file.write(html_content)

    return {"json": json_file_path, "html": html_file_path}


def _build_report_data_dict(session: ScanSessionResult) -> dict:
    critical_hosts = [p for p in session.host_risk_profiles if p.risk_level == RiskLevel.CRITICAL]
    high_risk_hosts = [p for p in session.host_risk_profiles if p.risk_level == RiskLevel.HIGH]

    return {
        "report_metadata": {
            "report_id": session.session_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_timestamp": session.scan_timestamp,
            "platform": "AI Cyber Fusion Platform v1.0",
        },
        "executive_summary": {
            "total_hosts_scanned": len(session.scanned_hosts),
            "total_alerts": len(session.threat_alerts),
            "critical_host_count": len(critical_hosts),
            "high_risk_host_count": len(high_risk_hosts),
            "attack_stories_count": len(session.attack_stories),
            "overall_risk_score": session.total_risk_score,
            "summary_text": session.executive_summary,
        },
        "top_risk_hosts": [
            _serialize_host_profile(profile)
            for profile in session.host_risk_profiles[:10]
        ],
        "threat_alerts": [
            _serialize_alert(alert)
            for alert in sorted(
                session.threat_alerts,
                key=lambda a: RISK_LEVEL_PRIORITY.get(a.risk_level, 3)
            )[:50]
        ],
        "attack_stories": [
            _serialize_attack_story(story)
            for story in session.attack_stories[:10]
        ],
        "attack_timeline": [
            {
                "event_time": event.event_time,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "description": event.event_description,
                "threat_category": event.threat_category.value,
                "mitre_technique": event.mitre_technique_id,
                "mitre_tactic": event.mitre_tactic_name,
                "risk_level": event.risk_level.value,
            }
            for event in session.timeline_events
        ],
        "mitre_coverage": _build_mitre_coverage_summary(session.threat_alerts),
    }


def _serialize_host_profile(profile: HostRiskProfile) -> dict:
    return {
        "ip_address": profile.ip_address,
        "hostname": profile.hostname,
        "risk_score": profile.risk_score,
        "risk_level": profile.risk_level.value,
        "open_port_count": profile.open_port_count,
        "critical_port_count": profile.critical_port_count,
        "anomaly_score": round(profile.anomaly_score, 3),
        "is_ml_anomaly": profile.is_ml_anomaly,
        "alert_count": len(profile.threat_alerts),
        "mitre_techniques": profile.mitre_techniques,
        "ai_explanation": profile.ai_explanation,
        "correlated_story": profile.correlated_story,
    }


def _serialize_alert(alert: ThreatAlertRecord) -> dict:
    return {
        "alert_id": alert.alert_id,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "threat_category": alert.threat_category.value,
        "risk_level": alert.risk_level.value,
        "confidence_score": round(alert.confidence_score, 3),
        "description": alert.description,
        "evidence": alert.evidence,
        "mitre_technique_id": alert.mitre_technique_id,
        "mitre_technique_name": alert.mitre_technique_name,
        "mitre_tactic_id": alert.mitre_tactic_id,
        "mitre_tactic_name": alert.mitre_tactic_name,
        "timestamp": alert.timestamp,
    }


def _serialize_attack_story(story: CorrelatedAttackStory) -> dict:
    return {
        "story_id": story.story_id,
        "involved_hosts": story.involved_ip_addresses,
        "risk_score": story.overall_risk_score,
        "risk_level": story.risk_level.value,
        "attack_narrative": story.attack_narrative,
        "mitre_tactics": story.mitre_tactics,
        "mitre_techniques": story.mitre_techniques,
        "timeline_event_count": len(story.timeline_events),
        "first_seen": story.first_seen,
        "last_seen": story.last_seen,
    }


def _build_mitre_coverage_summary(alerts: list[ThreatAlertRecord]) -> dict:
    tactic_counts: dict[str, int] = {}
    technique_counts: dict[str, int] = {}

    for alert in alerts:
        if alert.mitre_tactic_name:
            tactic_counts[alert.mitre_tactic_name] = tactic_counts.get(alert.mitre_tactic_name, 0) + 1
        if alert.mitre_technique_id:
            key = f"{alert.mitre_technique_id} - {alert.mitre_technique_name}"
            technique_counts[key] = technique_counts.get(key, 0) + 1

    return {
        "tactics_detected": tactic_counts,
        "techniques_detected": technique_counts,
    }


def _render_html_report(report_data: dict, session: ScanSessionResult) -> str:
    summary = report_data["executive_summary"]
    risk_color_map = {
        "Critical": "#dc2626",
        "High":     "#ea580c",
        "Medium":   "#ca8a04",
        "Low":      "#16a34a",
    }

    top_hosts_rows = ""
    for host in report_data["top_risk_hosts"]:
        color = risk_color_map.get(host["risk_level"], "#6b7280")
        top_hosts_rows += f"""
        <tr>
            <td><code>{host['ip_address']}</code></td>
            <td>{host['hostname'] or '—'}</td>
            <td style="color:{color};font-weight:bold">{host['risk_level']}</td>
            <td>{host['risk_score']}</td>
            <td>{host['open_port_count']}</td>
            <td>{host['alert_count']}</td>
            <td style="font-size:0.8em">{host['ai_explanation'][:120]}...</td>
        </tr>"""

    alert_rows = ""
    for alert in report_data["threat_alerts"]:
        color = risk_color_map.get(alert["risk_level"], "#6b7280")
        alert_rows += f"""
        <tr>
            <td style="color:{color};font-weight:bold">{alert['risk_level']}</td>
            <td>{alert['threat_category']}</td>
            <td><code>{alert['source_ip']}</code></td>
            <td style="font-size:0.85em">{alert['description'][:150]}</td>
            <td style="font-size:0.8em">{alert['mitre_technique_id']} {alert['mitre_technique_name']}</td>
        </tr>"""

    story_blocks = ""
    for story in report_data["attack_stories"]:
        color = risk_color_map.get(story["risk_level"], "#6b7280")
        story_blocks += f"""
        <div style="border-left:4px solid {color};padding:12px;margin:12px 0;background:#1e293b">
            <strong style="color:{color}">[{story['risk_level']}] Story {story['story_id']}</strong>
            — Risk Score: {story['risk_score']}<br>
            <em style="color:#94a3b8">{story['attack_narrative']}</em><br>
            <small style="color:#64748b">Hosts: {', '.join(story['involved_hosts'][:5])}
            | Tactics: {', '.join(story['mitre_tactics'][:3])}</small>
        </div>"""

    timeline_rows = ""
    for event in report_data["attack_timeline"][:30]:
        color = risk_color_map.get(event["risk_level"], "#6b7280")
        timeline_rows += f"""
        <tr>
            <td style="font-size:0.8em;color:#94a3b8">{event['event_time'][:19]}</td>
            <td><code>{event['source_ip']}</code></td>
            <td>{event['threat_category']}</td>
            <td style="color:{color}">{event['risk_level']}</td>
            <td style="font-size:0.85em">{event['description'][:100]}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Cyber Fusion — Security Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.5; }}
  .header {{ background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%); padding: 32px 40px; border-bottom: 1px solid #334155; }}
  .header h1 {{ font-size: 1.8em; color: #60a5fa; letter-spacing: 1px; }}
  .header .subtitle {{ color: #94a3b8; margin-top: 4px; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 24px 40px; }}
  .section {{ margin-bottom: 36px; }}
  .section-title {{ font-size: 1.2em; color: #60a5fa; border-bottom: 1px solid #334155; padding-bottom: 8px; margin-bottom: 16px; }}
  .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 24px; }}
  .kpi-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 16px; text-align: center; }}
  .kpi-value {{ font-size: 2em; font-weight: bold; color: #f8fafc; }}
  .kpi-label {{ font-size: 0.85em; color: #94a3b8; margin-top: 4px; }}
  .kpi-card.critical .kpi-value {{ color: #dc2626; }}
  .kpi-card.high .kpi-value {{ color: #ea580c; }}
  table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
  th {{ background: #0f172a; color: #94a3b8; padding: 10px 12px; text-align: left; font-size: 0.85em; text-transform: uppercase; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #334155; font-size: 0.9em; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #0f172a; }}
  code {{ background: #334155; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 0.9em; }}
  .footer {{ text-align: center; color: #475569; padding: 24px; font-size: 0.85em; border-top: 1px solid #334155; margin-top: 40px; }}
</style>
</head>
<body>
<div class="header">
  <h1>🛡 AI Cyber Fusion Platform — Security Report</h1>
  <div class="subtitle">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} &nbsp;|&nbsp; Report ID: {report_data['report_metadata']['report_id']}</div>
</div>
<div class="container">

  <div class="section">
    <div class="section-title">Executive Summary</div>
    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-value">{summary['total_hosts_scanned']}</div>
        <div class="kpi-label">Hosts Scanned</div>
      </div>
      <div class="kpi-card critical">
        <div class="kpi-value">{summary['critical_host_count']}</div>
        <div class="kpi-label">Critical Hosts</div>
      </div>
      <div class="kpi-card high">
        <div class="kpi-value">{summary['high_risk_host_count']}</div>
        <div class="kpi-label">High Risk Hosts</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-value">{summary['total_alerts']}</div>
        <div class="kpi-label">Total Alerts</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-value">{summary['attack_stories_count']}</div>
        <div class="kpi-label">Attack Stories</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-value">{summary['overall_risk_score']:.0f}</div>
        <div class="kpi-label">Overall Risk Score</div>
      </div>
    </div>
    <p style="color:#94a3b8;margin-top:8px">{summary['summary_text']}</p>
  </div>

  <div class="section">
    <div class="section-title">Top Risk Hosts</div>
    <table>
      <thead><tr>
        <th>IP Address</th><th>Hostname</th><th>Risk Level</th>
        <th>Score</th><th>Ports</th><th>Alerts</th><th>AI Explanation</th>
      </tr></thead>
      <tbody>{top_hosts_rows}</tbody>
    </table>
  </div>

  <div class="section">
    <div class="section-title">Correlated Attack Stories</div>
    {story_blocks if story_blocks else '<p style="color:#64748b">No correlated attack stories detected.</p>'}
  </div>

  <div class="section">
    <div class="section-title">Threat Alerts</div>
    <table>
      <thead><tr>
        <th>Risk</th><th>Category</th><th>Source IP</th><th>Description</th><th>MITRE Technique</th>
      </tr></thead>
      <tbody>{alert_rows}</tbody>
    </table>
  </div>

  <div class="section">
    <div class="section-title">Attack Timeline</div>
    <table>
      <thead><tr><th>Time</th><th>Source IP</th><th>Category</th><th>Risk</th><th>Description</th></tr></thead>
      <tbody>{timeline_rows}</tbody>
    </table>
  </div>

</div>
<div class="footer">AI Cyber Fusion Platform &nbsp;|&nbsp; Autonomous Threat Detection &amp; Behavioral Security Analysis</div>
</body>
</html>"""
