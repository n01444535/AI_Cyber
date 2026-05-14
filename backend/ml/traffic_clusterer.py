import numpy as np
from sklearn.cluster import DBSCAN, KMeans
from sklearn.preprocessing import StandardScaler

from backend.constants import DBSCAN_EPS, DBSCAN_MIN_SAMPLES
from backend.models import TrafficClusterRecord


CLUSTERING_FEATURE_COLUMNS = [
    "bytes_sent",
    "bytes_received",
    "unique_destination_count",
    "unique_port_contact_count",
    "dns_query_count",
    "syn_packet_count",
    "risky_port_contact_count",
    "outbound_to_inbound_ratio",
]

NOISE_CLUSTER_ID = -1


class TrafficClusterer:
    def __init__(self) -> None:
        self._feature_scaler: StandardScaler | None = None
        self._last_cluster_labels: np.ndarray | None = None

    def cluster_with_dbscan(
        self,
        host_traffic_features: list[dict],
        eps: float = DBSCAN_EPS,
        min_samples: int = DBSCAN_MIN_SAMPLES,
    ) -> list[TrafficClusterRecord]:
        if len(host_traffic_features) < min_samples:
            return []

        feature_matrix, host_ips = _prepare_feature_matrix(host_traffic_features)
        self._feature_scaler = StandardScaler()
        scaled_matrix = self._feature_scaler.fit_transform(feature_matrix)

        dbscan_clusterer = DBSCAN(eps=eps, min_samples=min_samples)
        cluster_labels = dbscan_clusterer.fit_predict(scaled_matrix)
        self._last_cluster_labels = cluster_labels

        return _build_cluster_records(cluster_labels, host_ips, host_traffic_features, "dbscan")

    def cluster_with_kmeans(
        self,
        host_traffic_features: list[dict],
        cluster_count: int = 4,
    ) -> list[TrafficClusterRecord]:
        if len(host_traffic_features) < cluster_count:
            cluster_count = max(2, len(host_traffic_features))

        feature_matrix, host_ips = _prepare_feature_matrix(host_traffic_features)
        self._feature_scaler = StandardScaler()
        scaled_matrix = self._feature_scaler.fit_transform(feature_matrix)

        kmeans_clusterer = KMeans(n_clusters=cluster_count, random_state=42, n_init=10)
        cluster_labels = kmeans_clusterer.fit_predict(scaled_matrix)
        self._last_cluster_labels = cluster_labels

        return _build_cluster_records(cluster_labels, host_ips, host_traffic_features, "kmeans")

    def label_clusters_by_behavior(
        self, cluster_records: list[TrafficClusterRecord], host_traffic_features: list[dict]
    ) -> list[TrafficClusterRecord]:
        features_by_ip = {f["ip_address"]: f for f in host_traffic_features}

        labeled_clusters: list[TrafficClusterRecord] = []
        for cluster in cluster_records:
            member_feature_list = [
                features_by_ip[ip_address]
                for ip_address in cluster.member_ips
                if ip_address in features_by_ip
            ]
            behavior_label = _infer_cluster_behavior_label(member_feature_list, cluster.is_noise)
            labeled_clusters.append(TrafficClusterRecord(
                cluster_id=cluster.cluster_id,
                member_ips=cluster.member_ips,
                centroid_features=cluster.centroid_features,
                cluster_label=behavior_label,
                is_noise=cluster.is_noise,
            ))

        return labeled_clusters


def _prepare_feature_matrix(host_traffic_features: list[dict]) -> tuple[np.ndarray, list[str]]:
    host_ips: list[str] = []
    rows: list[list[float]] = []

    for feature_dict in host_traffic_features:
        host_ips.append(feature_dict.get("ip_address", "unknown"))
        row = [float(feature_dict.get(col, 0)) for col in CLUSTERING_FEATURE_COLUMNS]
        rows.append(row)

    return np.array(rows), host_ips


def _build_cluster_records(
    cluster_labels: np.ndarray,
    host_ips: list[str],
    host_traffic_features: list[dict],
    algorithm_name: str,
) -> list[TrafficClusterRecord]:
    cluster_members: dict[int, list[str]] = {}
    cluster_feature_sums: dict[int, dict[str, float]] = {}

    for index, cluster_id in enumerate(cluster_labels):
        cluster_id_int = int(cluster_id)
        host_ip = host_ips[index]
        feature_dict = host_traffic_features[index]

        if cluster_id_int not in cluster_members:
            cluster_members[cluster_id_int] = []
            cluster_feature_sums[cluster_id_int] = {col: 0.0 for col in CLUSTERING_FEATURE_COLUMNS}

        cluster_members[cluster_id_int].append(host_ip)
        for col in CLUSTERING_FEATURE_COLUMNS:
            cluster_feature_sums[cluster_id_int][col] += float(feature_dict.get(col, 0))

    cluster_records: list[TrafficClusterRecord] = []
    for cluster_id_int, member_ips in cluster_members.items():
        member_count = len(member_ips)
        centroid_features = {
            col: round(cluster_feature_sums[cluster_id_int][col] / member_count, 2)
            for col in CLUSTERING_FEATURE_COLUMNS
        }
        cluster_records.append(TrafficClusterRecord(
            cluster_id=cluster_id_int,
            member_ips=member_ips,
            centroid_features=centroid_features,
            cluster_label="",
            is_noise=(cluster_id_int == NOISE_CLUSTER_ID),
        ))

    return sorted(cluster_records, key=lambda cluster: cluster.cluster_id)


def _infer_cluster_behavior_label(
    member_features: list[dict], is_noise: bool
) -> str:
    if is_noise:
        return "Outlier / Noise"
    if not member_features:
        return "Unknown"

    avg_risky_contacts = sum(f.get("risky_port_contact_count", 0) for f in member_features) / len(member_features)
    avg_unique_destinations = sum(f.get("unique_destination_count", 0) for f in member_features) / len(member_features)
    avg_dns_queries = sum(f.get("dns_query_count", 0) for f in member_features) / len(member_features)
    avg_bytes_sent = sum(f.get("bytes_sent", 0) for f in member_features) / len(member_features)
    avg_syn_count = sum(f.get("syn_packet_count", 0) for f in member_features) / len(member_features)

    high_risky_contact_threshold = 10
    high_destination_threshold = 50
    high_dns_threshold = 100
    high_bytes_threshold = 5_000_000
    high_syn_threshold = 200

    if avg_risky_contacts > high_risky_contact_threshold and avg_syn_count > high_syn_threshold:
        return "Aggressive Scanner / Attacker"
    if avg_unique_destinations > high_destination_threshold:
        return "Wide-Reach Scanner"
    if avg_dns_queries > high_dns_threshold:
        return "DNS-Heavy / Possible Tunneling"
    if avg_bytes_sent > high_bytes_threshold:
        return "High-Volume Sender / Possible Exfiltration"
    if avg_risky_contacts > 5:
        return "Risky Traffic Pattern"
    return "Normal Traffic"
