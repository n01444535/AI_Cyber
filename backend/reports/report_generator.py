import json
import os
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
    RiskLevel.HIGH: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.LOW: 3,
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
            _serialize_host_profile(profile) for profile in session.host_risk_profiles[:10]
        ],
        "threat_alerts": [
            _serialize_alert(alert)
            for alert in sorted(
                session.threat_alerts, key=lambda a: RISK_LEVEL_PRIORITY.get(a.risk_level, 3)
            )[:50]
        ],
        "attack_stories": [_serialize_attack_story(story) for story in session.attack_stories[:10]],
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
        "possible_false_positive": alert.possible_false_positive,
        "recommended_actions": alert.recommended_actions,
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


_MITRE_TACTIC_ORDER = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0010", "Exfiltration"),
    ("TA0011", "Command & Control"),
    ("TA0040", "Impact"),
]


def _build_mitre_heatmap_html(alerts: list[ThreatAlertRecord]) -> str:
    tactic_data: dict[str, dict] = {
        tactic_id: {"name": tactic_name, "alert_count": 0, "techniques": set()}
        for tactic_id, tactic_name in _MITRE_TACTIC_ORDER
    }

    for alert in alerts:
        tactic_id = alert.mitre_tactic_id
        if tactic_id in tactic_data:
            tactic_data[tactic_id]["alert_count"] += 1
            if alert.mitre_technique_id:
                tactic_data[tactic_id]["techniques"].add(alert.mitre_technique_id)

    cells = ""
    for tactic_id, data in tactic_data.items():
        alert_count = data["alert_count"]
        techniques = sorted(data["techniques"])

        if alert_count == 0:
            bg_color = "#1e293b"
            border_color = "#334155"
            text_color = "#475569"
            badge = ""
        elif alert_count == 1:
            bg_color = "#422006"
            border_color = "#ea580c"
            text_color = "#fed7aa"
            badge = f'<span style="background:#ea580c;color:#fff;border-radius:4px;padding:1px 6px;font-size:0.75em">{alert_count}</span>'
        else:
            bg_color = "#450a0a"
            border_color = "#dc2626"
            text_color = "#fca5a5"
            badge = f'<span style="background:#dc2626;color:#fff;border-radius:4px;padding:1px 6px;font-size:0.75em">{alert_count}</span>'

        technique_html = ""
        if techniques:
            technique_html = "".join(
                f'<div style="font-size:0.72em;color:#94a3b8;margin-top:2px">{t}</div>'
                for t in techniques[:3]
            )

        cells += f"""
        <div style="background:{bg_color};border:1px solid {border_color};border-radius:6px;
                    padding:10px;min-height:80px">
          <div style="font-size:0.78em;font-weight:bold;color:{text_color};margin-bottom:4px">
            {data['name']} {badge}
          </div>
          <div style="font-size:0.7em;color:#64748b">{tactic_id}</div>
          {technique_html}
        </div>"""

    return f"""
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px">
      {cells}
    </div>"""


def _build_mitre_coverage_summary(alerts: list[ThreatAlertRecord]) -> dict:
    tactic_counts: dict[str, int] = {}
    technique_counts: dict[str, int] = {}

    for alert in alerts:
        if alert.mitre_tactic_name:
            tactic_counts[alert.mitre_tactic_name] = (
                tactic_counts.get(alert.mitre_tactic_name, 0) + 1
            )
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
        "High": "#ea580c",
        "Medium": "#ca8a04",
        "Low": "#16a34a",
    }
    mitre_heatmap_html = _build_mitre_heatmap_html(session.threat_alerts)

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

    alert_cards = ""
    for alert in report_data["threat_alerts"]:
        color = risk_color_map.get(alert["risk_level"], "#6b7280")
        evidence_bullets = "".join(f"<li>{e}</li>" for e in alert.get("evidence", []))
        fp_bullets = "".join(
            f"<li>{fp}</li>" for fp in alert.get("possible_false_positive", [])
        )
        action_bullets = "".join(
            f"<li>{a}</li>" for a in alert.get("recommended_actions", [])
        )
        confidence_pct = int(alert["confidence_score"] * 100)
        alert_cards += f"""
        <div class="alert-card" style="border-left:4px solid {color}">
          <div class="alert-header">
            <span class="alert-badge" style="background:{color}">{alert['risk_level']}</span>
            <strong>{alert['threat_category']}</strong>
            &nbsp;&mdash;&nbsp;
            <code>{alert['source_ip']}</code>
            <span style="color:#64748b"> → </span>
            <code>{alert['destination_ip']}</code>
            <span class="confidence-badge">{confidence_pct}% confidence</span>
            <span style="float:right;font-size:0.8em;color:#64748b">{alert.get('timestamp','')[:19]}</span>
          </div>
          <p class="alert-desc">{alert['description']}</p>
          <div class="alert-detail-grid">
            <div class="detail-block">
              <div class="detail-title">Evidence</div>
              <ul>{evidence_bullets}</ul>
            </div>
            <div class="detail-block">
              <div class="detail-title">Possible False Positive</div>
              <ul class="fp-list">{fp_bullets if fp_bullets else '<li>None identified</li>'}</ul>
            </div>
            <div class="detail-block">
              <div class="detail-title">Recommended Actions</div>
              <ul class="action-list">{action_bullets if action_bullets else '<li>Investigate further</li>'}</ul>
            </div>
          </div>
          <div style="margin-top:8px;font-size:0.8em;color:#64748b">
            MITRE: <strong>{alert['mitre_technique_id']}</strong> {alert['mitre_technique_name']}
            &nbsp;|&nbsp; Tactic: {alert['mitre_tactic_name']}
          </div>
        </div>"""

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
  .header {{ background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%); padding: 24px 32px; border-bottom: 1px solid #334155; }}
  .header h1 {{ font-size: 1.6em; color: #60a5fa; letter-spacing: 1px; }}
  .header .subtitle {{ color: #94a3b8; margin-top: 4px; font-size: 0.9em; }}
  .layout {{ display: flex; min-height: 100vh; }}
  .sidebar {{
    width: 190px; min-width: 190px; background: #0b1120; border-right: 1px solid #1e293b;
    padding: 24px 0; position: sticky; top: 0; height: 100vh; overflow-y: auto;
    flex-shrink: 0;
  }}
  .sidebar-title {{ font-size: 0.7em; text-transform: uppercase; color: #475569;
                    letter-spacing: 1px; padding: 0 16px 12px; font-weight: bold; }}
  .sidebar a {{
    display: block; padding: 8px 16px; color: #64748b; font-size: 0.82em;
    text-decoration: none; border-left: 3px solid transparent; transition: all 0.15s;
  }}
  .sidebar a:hover {{ color: #60a5fa; border-left-color: #60a5fa; background: #1e293b; }}
  .sidebar .nav-count {{
    float: right; background: #1e293b; border-radius: 10px; padding: 1px 7px;
    font-size: 0.75em; color: #94a3b8;
  }}
  .container {{ flex: 1; max-width: 1300px; padding: 24px 36px; overflow-x: auto; }}
  .section {{ margin-bottom: 36px; scroll-margin-top: 16px; }}
  .section-title {{ font-size: 1.15em; color: #60a5fa; border-bottom: 1px solid #334155;
                    padding-bottom: 8px; margin-bottom: 16px; }}
  .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
               gap: 14px; margin-bottom: 20px; }}
  .kpi-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px;
               padding: 14px; text-align: center; }}
  .kpi-value {{ font-size: 2em; font-weight: bold; color: #f8fafc; }}
  .kpi-label {{ font-size: 0.82em; color: #94a3b8; margin-top: 4px; }}
  .kpi-card.critical .kpi-value {{ color: #dc2626; }}
  .kpi-card.high .kpi-value {{ color: #ea580c; }}
  table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
  th {{ background: #0f172a; color: #94a3b8; padding: 10px 12px; text-align: left;
        font-size: 0.82em; text-transform: uppercase; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #334155; font-size: 0.88em; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #0f172a; }}
  code {{ background: #334155; padding: 2px 6px; border-radius: 4px;
          font-family: monospace; font-size: 0.88em; }}
  .footer {{ text-align: center; color: #475569; padding: 24px; font-size: 0.82em;
             border-top: 1px solid #334155; margin-top: 40px; }}
  .alert-card {{ background: #1e293b; border-radius: 8px; padding: 16px; margin-bottom: 12px; }}
  .alert-header {{ margin-bottom: 8px; font-size: 0.93em; }}
  .alert-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px;
                  color: #fff; font-size: 0.78em; font-weight: bold; margin-right: 8px; }}
  .confidence-badge {{ display: inline-block; background: #334155; padding: 2px 8px;
                       border-radius: 4px; font-size: 0.78em; color: #94a3b8; margin-left: 12px; }}
  .alert-desc {{ color: #cbd5e1; font-size: 0.88em; margin-bottom: 12px; }}
  .alert-detail-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; }}
  .detail-block {{ background: #0f172a; border-radius: 6px; padding: 10px 12px; }}
  .detail-title {{ font-size: 0.72em; text-transform: uppercase; color: #64748b;
                   letter-spacing: 0.5px; margin-bottom: 6px; font-weight: bold; }}
  .detail-block ul {{ padding-left: 16px; margin: 0; }}
  .detail-block li {{ font-size: 0.8em; color: #94a3b8; margin-bottom: 3px; }}
  .fp-list li {{ color: #fbbf24; }}
  .action-list li {{ color: #34d399; }}
</style>
</head>
<body>
<div class="header">
  <h1>&#x1F6E1; AI Cyber Fusion Platform &mdash; Security Report</h1>
  <div class="subtitle">
    Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
    &nbsp;&nbsp;|&nbsp;&nbsp;
    Report ID: {report_data['report_metadata']['report_id']}
  </div>
</div>

<div class="layout">
  <nav class="sidebar">
    <div class="sidebar-title">Sections</div>
    <a href="#summary">&#x1F4CA; Executive Summary</a>
    <a href="#hosts">&#x1F5A5; Top Risk Hosts
      <span class="nav-count">{len(report_data['top_risk_hosts'])}</span>
    </a>
    <a href="#stories">&#x1F4D6; Attack Stories
      <span class="nav-count">{len(report_data['attack_stories'])}</span>
    </a>
    <a href="#mitre">&#x1F5FA; MITRE ATT&amp;CK</a>
    <a href="#alerts">&#x26A0; Alerts
      <span class="nav-count">{len(report_data['threat_alerts'])}</span>
    </a>
    <a href="#timeline">&#x23F1; Timeline</a>
  </nav>

  <div class="container">

    <div class="section" id="summary">
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

    <div class="section" id="hosts">
      <div class="section-title">Top Risk Hosts</div>
      <table>
        <thead><tr>
          <th>IP Address</th><th>Hostname</th><th>Risk Level</th>
          <th>Score</th><th>Ports</th><th>Alerts</th><th>AI Explanation</th>
        </tr></thead>
        <tbody>{top_hosts_rows}</tbody>
      </table>
    </div>

    <div class="section" id="stories">
      <div class="section-title">Correlated Attack Stories</div>
      {story_blocks if story_blocks else '<p style="color:#64748b">No correlated attack stories detected.</p>'}
    </div>

    <div class="section" id="mitre">
      <div class="section-title">MITRE ATT&amp;CK Coverage</div>
      {mitre_heatmap_html}
    </div>

    <div class="section" id="alerts">
      <div class="section-title">Threat Alerts ({len(report_data['threat_alerts'])})</div>
      {alert_cards if alert_cards else '<p style="color:#64748b">No threat alerts detected.</p>'}
    </div>

    <div class="section" id="timeline">
      <div class="section-title">Attack Timeline</div>
      <table>
        <thead><tr><th>Time</th><th>Source IP</th><th>Category</th><th>Risk</th><th>Description</th></tr></thead>
        <tbody>{timeline_rows if timeline_rows else '<tr><td colspan="5" style="color:#64748b;text-align:center">No timeline events.</td></tr>'}</tbody>
      </table>
    </div>

  </div>
</div>

<div class="footer">AI Cyber Fusion Platform &nbsp;|&nbsp; Autonomous Threat Detection &amp; Behavioral Security Analysis</div>
</body>
</html>"""
