"""
Compare a PCAP against a saved baseline and surface significant deviations.

A deviation is flagged when a per-host metric exceeds:
    baseline_mean + DEVIATION_STDEV_MULTIPLIER × baseline_stdev

Each deviation becomes a lightweight finding dict that callers can print or
pass to the report generator.
"""

from backend.baseline.baseline_builder import _compute_per_host_stats, load_baseline
from backend.packet_analyzer.pcap_parser import parse_pcap_file
from backend.packet_analyzer.traffic_analyzer import build_network_flows

DEVIATION_STDEV_MULTIPLIER = 3.0

METRIC_LABELS: dict[str, str] = {
    "bytes_sent": "bytes sent",
    "bytes_received": "bytes received",
    "unique_destination_count": "unique destinations contacted",
    "unique_port_contact_count": "unique ports contacted",
    "dns_query_count": "DNS queries",
    "syn_packet_count": "SYN packets",
    "outbound_to_inbound_ratio": "outbound:inbound ratio",
}


def compare_pcap_to_baseline(
    pcap_path: str,
    baseline_path: str,
) -> list[dict]:
    baseline = load_baseline(baseline_path)
    global_stats = baseline.get("global", {})

    packet_records = parse_pcap_file(pcap_path)
    network_flows = build_network_flows(packet_records)
    observed_host_stats = _compute_per_host_stats(packet_records, network_flows)

    deviations: list[dict] = []
    for host_ip, observed_metrics in observed_host_stats.items():
        host_deviations = _detect_host_deviations(host_ip, observed_metrics, global_stats)
        deviations.extend(host_deviations)

    deviations.sort(key=lambda d: d["deviation_factor"], reverse=True)
    return deviations


def _detect_host_deviations(
    host_ip: str,
    observed: dict,
    global_stats: dict,
) -> list[dict]:
    findings: list[dict] = []

    for metric_key, label in METRIC_LABELS.items():
        baseline_entry = global_stats.get(metric_key)
        if not baseline_entry:
            continue

        baseline_mean = baseline_entry["mean"]
        baseline_stdev = baseline_entry["stdev"]
        observed_value = observed.get(metric_key, 0)

        threshold = baseline_mean + DEVIATION_STDEV_MULTIPLIER * max(baseline_stdev, 1.0)
        if observed_value <= threshold:
            continue

        deviation_factor = observed_value / max(threshold, 1.0)
        findings.append(
            {
                "host_ip": host_ip,
                "metric": metric_key,
                "label": label,
                "observed_value": observed_value,
                "baseline_mean": baseline_mean,
                "threshold": threshold,
                "deviation_factor": round(deviation_factor, 2),
                "description": (
                    f"{host_ip} — {label}: observed {observed_value:,.0f}, "
                    f"baseline mean {baseline_mean:,.0f} "
                    f"({deviation_factor:.1f}× above threshold)"
                ),
            }
        )

    return findings
