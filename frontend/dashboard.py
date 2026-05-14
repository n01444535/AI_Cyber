from datetime import datetime, timezone

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from backend.models import (
    CorrelatedAttackStory,
    HostRiskProfile,
    RiskLevel,
    ScanSessionResult,
    ThreatAlertRecord,
)


RISK_COLOR_MAP = {
    RiskLevel.CRITICAL: "bold red",
    RiskLevel.HIGH:     "bold orange3",
    RiskLevel.MEDIUM:   "bold yellow",
    RiskLevel.LOW:      "bold green",
}

CYBER_THEME = Theme({
    "critical": "bold red",
    "high":     "bold orange3",
    "medium":   "bold yellow",
    "low":      "bold green",
    "info":     "cyan",
    "muted":    "dim white",
    "header":   "bold blue",
    "ip":       "bold cyan",
    "mitre":    "bold magenta",
})

_console = Console(theme=CYBER_THEME)


def render_full_session_dashboard(session: ScanSessionResult) -> None:
    _console.clear()
    _render_platform_header()
    _render_executive_kpis(session)
    _render_top_risk_hosts(session.host_risk_profiles[:10])
    _render_threat_alerts(session.threat_alerts[:20])
    _render_attack_stories(session.attack_stories[:5])
    _render_attack_timeline(session)
    _render_mitre_coverage(session.threat_alerts)
    _render_footer()


def render_host_explanation(session: ScanSessionResult, target_ip: str) -> None:
    matching_profile = next(
        (p for p in session.host_risk_profiles if p.ip_address == target_ip), None
    )
    if not matching_profile:
        _console.print(f"[red]Host {target_ip} not found in session results.[/red]")
        return

    _render_host_detail_panel(matching_profile)


def _render_platform_header() -> None:
    header_text = Text()
    header_text.append("🛡  AI CYBER FUSION PLATFORM  ", style="bold blue")
    header_text.append("Autonomous Threat Detection & Behavioral Security Analysis", style="dim white")

    timestamp_string = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    _console.print(Panel(
        header_text,
        subtitle=f"[dim]{timestamp_string}[/dim]",
        border_style="blue",
        padding=(0, 2),
    ))


def _render_executive_kpis(session: ScanSessionResult) -> None:
    critical_count = sum(1 for p in session.host_risk_profiles if p.risk_level == RiskLevel.CRITICAL)
    high_count     = sum(1 for p in session.host_risk_profiles if p.risk_level == RiskLevel.HIGH)
    anomaly_count  = sum(1 for p in session.host_risk_profiles if p.is_ml_anomaly)

    kpi_panels = [
        Panel(f"[bold white]{len(session.scanned_hosts) or len(session.host_risk_profiles)}[/bold white]",
              title="Hosts", border_style="blue"),
        Panel(f"[critical]{critical_count}[/critical]",
              title="Critical", border_style="red"),
        Panel(f"[high]{high_count}[/high]",
              title="High Risk", border_style="orange3"),
        Panel(f"[bold white]{len(session.threat_alerts)}[/bold white]",
              title="Alerts", border_style="yellow"),
        Panel(f"[bold white]{len(session.attack_stories)}[/bold white]",
              title="Attack Stories", border_style="magenta"),
        Panel(f"[bold white]{anomaly_count}[/bold white]",
              title="ML Anomalies", border_style="cyan"),
        Panel(f"[bold white]{session.total_risk_score:.0f}[/bold white]",
              title="Risk Score", border_style="red" if session.total_risk_score >= 80 else "yellow"),
    ]
    _console.print(Columns(kpi_panels, equal=True, expand=True))

    if session.executive_summary:
        _console.print(Panel(
            f"[muted]{session.executive_summary}[/muted]",
            title="[header]Executive Summary[/header]",
            border_style="blue",
        ))


def _render_top_risk_hosts(host_profiles: list[HostRiskProfile]) -> None:
    if not host_profiles:
        return

    host_table = Table(
        title="[header]Top Risk Hosts[/header]",
        box=box.ROUNDED,
        border_style="blue",
        show_lines=False,
    )
    host_table.add_column("IP Address",  style="ip",     min_width=16)
    host_table.add_column("Hostname",    style="muted",  max_width=24)
    host_table.add_column("Risk Level",  min_width=10)
    host_table.add_column("Score",       justify="right", min_width=6)
    host_table.add_column("Ports",       justify="right", min_width=5)
    host_table.add_column("Alerts",      justify="right", min_width=6)
    host_table.add_column("ML Anomaly",  justify="center", min_width=10)
    host_table.add_column("AI Explanation", max_width=55, no_wrap=True)

    for profile in host_profiles:
        risk_color = RISK_COLOR_MAP[profile.risk_level]
        anomaly_indicator = "[red]YES[/red]" if profile.is_ml_anomaly else "[muted]no[/muted]"
        explanation_short = profile.ai_explanation[:80] + "…" if len(profile.ai_explanation) > 80 else profile.ai_explanation

        host_table.add_row(
            profile.ip_address,
            profile.hostname or "—",
            f"[{risk_color}]{profile.risk_level.value}[/{risk_color}]",
            f"{profile.risk_score:.1f}",
            str(profile.open_port_count),
            str(len(profile.threat_alerts)),
            anomaly_indicator,
            f"[muted]{explanation_short}[/muted]",
        )

    _console.print(host_table)


def _render_threat_alerts(threat_alerts: list[ThreatAlertRecord]) -> None:
    if not threat_alerts:
        _console.print(Panel("[low]No threats detected.[/low]", title="[header]Threat Alerts[/header]", border_style="green"))
        return

    alert_table = Table(
        title=f"[header]Threat Alerts[/header] [muted]({len(threat_alerts)} shown)[/muted]",
        box=box.SIMPLE_HEAD,
        border_style="yellow",
        show_lines=False,
    )
    alert_table.add_column("Risk",      min_width=10)
    alert_table.add_column("Category",  min_width=20)
    alert_table.add_column("Source IP", style="ip", min_width=16)
    alert_table.add_column("Confidence", justify="right", min_width=10)
    alert_table.add_column("Description", max_width=60, no_wrap=True)
    alert_table.add_column("MITRE",     style="mitre", min_width=12)

    sorted_alerts = sorted(threat_alerts, key=lambda a: a.confidence_score, reverse=True)
    for alert in sorted_alerts:
        risk_color = RISK_COLOR_MAP[alert.risk_level]
        alert_table.add_row(
            f"[{risk_color}]{alert.risk_level.value}[/{risk_color}]",
            alert.threat_category.value,
            alert.source_ip,
            f"{alert.confidence_score:.0%}",
            alert.description[:80],
            alert.mitre_technique_id,
        )

    _console.print(alert_table)


def _render_attack_stories(attack_stories: list[CorrelatedAttackStory]) -> None:
    if not attack_stories:
        return

    _console.print(Panel(
        title="[header]Correlated Attack Stories[/header]",
        renderable=_build_stories_renderable(attack_stories),
        border_style="magenta",
    ))


def _build_stories_renderable(attack_stories: list[CorrelatedAttackStory]) -> Text:
    renderable = Text()
    for index, story in enumerate(attack_stories, start=1):
        risk_color = RISK_COLOR_MAP[story.risk_level]
        renderable.append(f"\n[Story {index}] ", style="bold white")
        renderable.append(f"{story.risk_level.value}", style=risk_color)
        renderable.append(f" — Score: {story.overall_risk_score:.0f}", style="white")
        renderable.append(f"\nHosts: {', '.join(story.involved_ip_addresses[:4])}", style="cyan")
        renderable.append(f"\nTactics: {', '.join(story.mitre_tactics[:3])}", style="magenta")
        renderable.append(f"\n{story.attack_narrative[:200]}", style="dim white")
        renderable.append("\n")
    return renderable


def _render_attack_timeline(session: ScanSessionResult) -> None:
    all_timeline_events = list(session.timeline_events)
    for story in session.attack_stories:
        for event in story.timeline_events:
            if event not in all_timeline_events:
                all_timeline_events.append(event)

    if not all_timeline_events:
        return

    sorted_events = sorted(all_timeline_events, key=lambda e: e.event_time)[:20]

    timeline_table = Table(
        title="[header]Attack Timeline[/header]",
        box=box.MINIMAL_DOUBLE_HEAD,
        border_style="cyan",
    )
    timeline_table.add_column("Time",        style="muted",  min_width=20)
    timeline_table.add_column("Source IP",   style="ip",     min_width=16)
    timeline_table.add_column("Category",    min_width=20)
    timeline_table.add_column("Risk",        min_width=10)
    timeline_table.add_column("MITRE",       style="mitre",  min_width=12)
    timeline_table.add_column("Description", max_width=55,   no_wrap=True)

    for event in sorted_events:
        risk_color = RISK_COLOR_MAP[event.risk_level]
        timeline_table.add_row(
            event.event_time[:19] if event.event_time else "—",
            event.source_ip,
            event.threat_category.value,
            f"[{risk_color}]{event.risk_level.value}[/{risk_color}]",
            event.mitre_technique_id or "—",
            event.event_description[:60],
        )

    _console.print(timeline_table)


def _render_mitre_coverage(threat_alerts: list[ThreatAlertRecord]) -> None:
    tactic_counts: dict[str, int] = {}
    technique_counts: dict[str, int] = {}

    for alert in threat_alerts:
        if alert.mitre_tactic_name:
            tactic_counts[alert.mitre_tactic_name] = tactic_counts.get(alert.mitre_tactic_name, 0) + 1
        if alert.mitre_technique_id:
            key = f"{alert.mitre_technique_id} {alert.mitre_technique_name}"
            technique_counts[key] = technique_counts.get(key, 0) + 1

    if not tactic_counts:
        return

    mitre_table = Table(
        title="[header]MITRE ATT&CK Coverage[/header]",
        box=box.SIMPLE,
        border_style="magenta",
    )
    mitre_table.add_column("Tactic",    style="mitre",      min_width=25)
    mitre_table.add_column("Count",     justify="right",    min_width=8)
    mitre_table.add_column("Technique", style="muted",      min_width=35)

    for tactic_name, tactic_count in sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True):
        related_techniques = [
            tech_key for tech_key in technique_counts
            if any(alert.mitre_tactic_name == tactic_name and f"{alert.mitre_technique_id} " in tech_key
                   for alert in threat_alerts)
        ]
        mitre_table.add_row(
            tactic_name,
            str(tactic_count),
            ", ".join(related_techniques[:2]) if related_techniques else "—",
        )

    _console.print(mitre_table)


def _render_host_detail_panel(profile: HostRiskProfile) -> None:
    risk_color = RISK_COLOR_MAP[profile.risk_level]
    detail_text = Text()

    detail_text.append(f"\n  Host: ", style="bold white")
    detail_text.append(profile.ip_address, style="ip")
    if profile.hostname:
        detail_text.append(f" ({profile.hostname})", style="muted")

    detail_text.append(f"\n  Risk Level: ", style="bold white")
    detail_text.append(f"{profile.risk_level.value}", style=risk_color)
    detail_text.append(f"  |  Score: {profile.risk_score:.1f}/100", style="white")

    detail_text.append(f"\n  Open Ports: {profile.open_port_count}", style="white")
    detail_text.append(f"  |  Critical Ports: {profile.critical_port_count}", style="critical" if profile.critical_port_count > 0 else "white")
    detail_text.append(f"  |  ML Anomaly: ", style="white")
    detail_text.append("YES" if profile.is_ml_anomaly else "No",
                        style="red bold" if profile.is_ml_anomaly else "muted")

    detail_text.append(f"\n\n  AI Explanation:\n  ", style="bold white")
    detail_text.append(profile.ai_explanation, style="dim white")

    if profile.mitre_techniques:
        detail_text.append(f"\n\n  MITRE Techniques: ", style="bold white")
        detail_text.append(", ".join(profile.mitre_techniques), style="mitre")

    if profile.correlated_story:
        detail_text.append(f"\n\n  Correlated Attack Story:\n  ", style="bold white")
        detail_text.append(profile.correlated_story[:300], style="dim white")

    if profile.threat_alerts:
        detail_text.append(f"\n\n  Active Alerts ({len(profile.threat_alerts)}):\n", style="bold white")
        for alert in profile.threat_alerts[:5]:
            alert_risk_color = RISK_COLOR_MAP[alert.risk_level]
            detail_text.append(f"   • [{alert.risk_level.value}] ", style=alert_risk_color)
            detail_text.append(f"{alert.threat_category.value}: {alert.description[:80]}\n", style="white")

    _console.print(Panel(
        detail_text,
        title=f"[header]Host Analysis — {profile.ip_address}[/header]",
        border_style=risk_color.replace("bold ", ""),
        padding=(0, 2),
    ))


def _render_footer() -> None:
    _console.print(
        Panel(
            "[muted]AI Cyber Fusion Platform  |  Autonomous Threat Detection & Behavioral Security Analysis[/muted]",
            border_style="dim blue",
            padding=(0, 2),
        )
    )


def print_quick_summary(session: ScanSessionResult) -> None:
    critical_count = sum(1 for p in session.host_risk_profiles if p.risk_level == RiskLevel.CRITICAL)
    _console.print(f"\n[header]Scan complete.[/header] "
                   f"Hosts: [bold white]{len(session.host_risk_profiles)}[/bold white]  "
                   f"Alerts: [bold white]{len(session.threat_alerts)}[/bold white]  "
                   f"Critical: [critical]{critical_count}[/critical]  "
                   f"Stories: [bold white]{len(session.attack_stories)}[/bold white]\n")
