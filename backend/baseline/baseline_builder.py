"""
Build a per-host traffic baseline from a PCAP representing normal network activity.

Baseline metrics per host:
  - bytes_sent_mean / bytes_sent_std
  - bytes_received_mean / bytes_received_std
  - unique_destination_count_mean
  - unique_port_contact_count_mean
  - dns_query_count_mean
  - syn_packet_count_mean
  - outbound_to_inbound_ratio_mean

Saved as JSON to BASELINE_DEFAULT_PATH (or a caller-supplied path).
"""

import json
import statistics
from collections import defaultdict
from datetime import datetime, timezone

from backend.packet_analyzer.pcap_parser import parse_pcap_file
from backend.packet_analyzer.traffic_analyzer import build_network_flows

BASELINE_DEFAULT_PATH = "baseline.json"

BASELINE_VERSION = "1"


def build_baseline_from_pcap(pcap_path: str, output_path: str = BASELINE_DEFAULT_PATH) -> dict:
    packet_records = parse_pcap_file(pcap_path)
    if not packet_records:
        raise ValueError(f"No packets parsed from {pcap_path}")

    network_flows = build_network_flows(packet_records)
    host_stats = _compute_per_host_stats(packet_records, network_flows)
    baseline = _aggregate_baseline_stats(host_stats, pcap_path)

    with open(output_path, "w") as baseline_file:
        json.dump(baseline, baseline_file, indent=2)

    return baseline


def _compute_per_host_stats(packet_records, network_flows) -> dict[str, dict]:
    bytes_sent: dict[str, int] = defaultdict(int)
    bytes_received: dict[str, int] = defaultdict(int)
    unique_dests: dict[str, set] = defaultdict(set)
    unique_ports: dict[str, set] = defaultdict(set)
    dns_queries: dict[str, int] = defaultdict(int)
    syn_count: dict[str, int] = defaultdict(int)

    for flow in network_flows:
        bytes_sent[flow.source_ip] += flow.byte_count
        bytes_received[flow.destination_ip] += flow.byte_count
        unique_dests[flow.source_ip].add(flow.destination_ip)
        unique_ports[flow.source_ip].add(flow.destination_port)
        syn_count[flow.source_ip] += flow.syn_count

    for packet in packet_records:
        if packet.dns_query_name:
            dns_queries[packet.source_ip] += 1

    all_ips = set(bytes_sent) | set(bytes_received)
    host_stats: dict[str, dict] = {}
    for ip in all_ips:
        sent = bytes_sent[ip]
        received = max(bytes_received[ip], 1)
        host_stats[ip] = {
            "bytes_sent": sent,
            "bytes_received": received,
            "unique_destination_count": len(unique_dests[ip]),
            "unique_port_contact_count": len(unique_ports[ip]),
            "dns_query_count": dns_queries[ip],
            "syn_packet_count": syn_count[ip],
            "outbound_to_inbound_ratio": sent / received,
        }
    return host_stats


def _aggregate_baseline_stats(host_stats: dict[str, dict], pcap_path: str) -> dict:
    if not host_stats:
        return {}

    metric_keys = [
        "bytes_sent",
        "bytes_received",
        "unique_destination_count",
        "unique_port_contact_count",
        "dns_query_count",
        "syn_packet_count",
        "outbound_to_inbound_ratio",
    ]

    aggregated: dict[str, dict] = {}
    for metric in metric_keys:
        values = [stats[metric] for stats in host_stats.values()]
        aggregated[metric] = {
            "mean": statistics.mean(values),
            "stdev": statistics.pstdev(values),
            "max": max(values),
        }

    return {
        "version": BASELINE_VERSION,
        "source_pcap": pcap_path,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "host_count": len(host_stats),
        "per_host": host_stats,
        "global": aggregated,
    }


def load_baseline(baseline_path: str = BASELINE_DEFAULT_PATH) -> dict:
    with open(baseline_path) as baseline_file:
        return json.load(baseline_file)
