import os
import pickle
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from backend.constants import (
    ANOMALY_HIGH_THRESHOLD,
    ISOLATION_FOREST_CONTAMINATION,
    ISOLATION_FOREST_N_ESTIMATORS,
    MIN_SAMPLES_TO_TRAIN,
)
from backend.models import AnomalyDetectionResult

TRAFFIC_FEATURE_COLUMNS = [
    "bytes_sent",
    "bytes_received",
    "unique_destination_count",
    "unique_port_contact_count",
    "dns_query_count",
    "syn_packet_count",
    "rst_packet_count",
    "risky_port_contact_count",
    "outbound_to_inbound_ratio",
]

HOST_FEATURE_COLUMNS = [
    "open_port_count",
    "high_risk_port_count",
    "critical_port_count",
    "remote_access_port_count",
    "database_port_count",
    "fileshare_port_count",
    "cleartext_port_count",
    "admin_port_count",
    "has_smb",
    "has_rdp",
    "has_ssh",
    "has_telnet",
    "has_ftp",
    "has_db_exposed",
    "has_docker_api",
]


class TrafficAnomalyDetector:
    def __init__(self) -> None:
        self._isolation_forest_model: IsolationForest | None = None
        self._feature_scaler: StandardScaler | None = None
        self._is_trained: bool = False

    def train(self, host_traffic_features: list[dict]) -> None:
        feature_matrix = _extract_feature_matrix(host_traffic_features, TRAFFIC_FEATURE_COLUMNS)
        if len(feature_matrix) < MIN_SAMPLES_TO_TRAIN:
            return

        self._feature_scaler = StandardScaler()
        scaled_feature_matrix = self._feature_scaler.fit_transform(feature_matrix)

        self._isolation_forest_model = IsolationForest(
            n_estimators=ISOLATION_FOREST_N_ESTIMATORS,
            contamination=ISOLATION_FOREST_CONTAMINATION,
            random_state=42,
        )
        self._isolation_forest_model.fit(scaled_feature_matrix)
        self._is_trained = True

    def detect_anomalies(self, host_traffic_features: list[dict]) -> list[AnomalyDetectionResult]:
        if not self._is_trained or not host_traffic_features:
            return _build_heuristic_anomaly_results(host_traffic_features, TRAFFIC_FEATURE_COLUMNS)

        feature_matrix = _extract_feature_matrix(host_traffic_features, TRAFFIC_FEATURE_COLUMNS)
        scaled_matrix = self._feature_scaler.transform(feature_matrix)

        raw_anomaly_scores = self._isolation_forest_model.score_samples(scaled_matrix)
        # Convert to [0, 1] where 1 = most anomalous
        normalized_scores = 1 - (raw_anomaly_scores - raw_anomaly_scores.min()) / (
            raw_anomaly_scores.max() - raw_anomaly_scores.min() + 1e-9
        )

        results: list[AnomalyDetectionResult] = []
        for index, feature_dict in enumerate(host_traffic_features):
            anomaly_score = float(normalized_scores[index])
            contributing_features = _identify_contributing_features(
                feature_dict, host_traffic_features, TRAFFIC_FEATURE_COLUMNS
            )
            results.append(
                AnomalyDetectionResult(
                    ip_address=feature_dict.get("ip_address", "unknown"),
                    anomaly_score=anomaly_score,
                    is_anomaly=anomaly_score >= ANOMALY_HIGH_THRESHOLD,
                    contributing_features=contributing_features,
                )
            )

        return results

    def save_model(self, model_save_path: str) -> None:
        if not self._is_trained:
            return
        Path(model_save_path).mkdir(parents=True, exist_ok=True)
        model_file_path = os.path.join(model_save_path, "traffic_anomaly_detector.pkl")
        with open(model_file_path, "wb") as model_file:
            pickle.dump(
                {"model": self._isolation_forest_model, "scaler": self._feature_scaler}, model_file
            )

    def load_model(self, model_save_path: str) -> bool:
        model_file_path = os.path.join(model_save_path, "traffic_anomaly_detector.pkl")
        if not Path(model_file_path).exists():
            return False
        with open(model_file_path, "rb") as model_file:
            saved_data = pickle.load(model_file)
        self._isolation_forest_model = saved_data["model"]
        self._feature_scaler = saved_data["scaler"]
        self._is_trained = True
        return True


class HostAnomalyDetector:
    def __init__(self) -> None:
        self._isolation_forest_model: IsolationForest | None = None
        self._feature_scaler: StandardScaler | None = None
        self._is_trained: bool = False

    def train(self, host_scan_features: list[dict]) -> None:
        feature_matrix = _extract_feature_matrix(host_scan_features, HOST_FEATURE_COLUMNS)
        if len(feature_matrix) < MIN_SAMPLES_TO_TRAIN:
            return

        self._feature_scaler = StandardScaler()
        scaled_matrix = self._feature_scaler.fit_transform(feature_matrix)

        self._isolation_forest_model = IsolationForest(
            n_estimators=ISOLATION_FOREST_N_ESTIMATORS,
            contamination=ISOLATION_FOREST_CONTAMINATION,
            random_state=42,
        )
        self._isolation_forest_model.fit(scaled_matrix)
        self._is_trained = True

    def detect_anomalies(self, host_scan_features: list[dict]) -> list[AnomalyDetectionResult]:
        if not self._is_trained or not host_scan_features:
            return _build_heuristic_anomaly_results(host_scan_features, HOST_FEATURE_COLUMNS)

        feature_matrix = _extract_feature_matrix(host_scan_features, HOST_FEATURE_COLUMNS)
        scaled_matrix = self._feature_scaler.transform(feature_matrix)

        raw_scores = self._isolation_forest_model.score_samples(scaled_matrix)
        normalized_scores = 1 - (raw_scores - raw_scores.min()) / (
            raw_scores.max() - raw_scores.min() + 1e-9
        )

        results: list[AnomalyDetectionResult] = []
        for index, feature_dict in enumerate(host_scan_features):
            anomaly_score = float(normalized_scores[index])
            contributing_features = _identify_contributing_features(
                feature_dict, host_scan_features, HOST_FEATURE_COLUMNS
            )
            results.append(
                AnomalyDetectionResult(
                    ip_address=feature_dict.get("ip_address", "unknown"),
                    anomaly_score=anomaly_score,
                    is_anomaly=anomaly_score >= ANOMALY_HIGH_THRESHOLD,
                    contributing_features=contributing_features,
                )
            )

        return results

    def save_model(self, model_save_path: str) -> None:
        if not self._is_trained:
            return
        Path(model_save_path).mkdir(parents=True, exist_ok=True)
        model_file_path = os.path.join(model_save_path, "host_anomaly_detector.pkl")
        with open(model_file_path, "wb") as model_file:
            pickle.dump(
                {"model": self._isolation_forest_model, "scaler": self._feature_scaler}, model_file
            )

    def load_model(self, model_save_path: str) -> bool:
        model_file_path = os.path.join(model_save_path, "host_anomaly_detector.pkl")
        if not Path(model_file_path).exists():
            return False
        with open(model_file_path, "rb") as model_file:
            saved_data = pickle.load(model_file)
        self._isolation_forest_model = saved_data["model"]
        self._feature_scaler = saved_data["scaler"]
        self._is_trained = True
        return True


def _extract_feature_matrix(feature_dicts: list[dict], column_names: list[str]) -> np.ndarray:
    rows = []
    for feature_dict in feature_dicts:
        row = [float(feature_dict.get(col, 0)) for col in column_names]
        rows.append(row)
    return np.array(rows)


def _identify_contributing_features(
    target_dict: dict,
    all_dicts: list[dict],
    column_names: list[str],
) -> list[str]:
    if len(all_dicts) < 2:
        return []

    contributing: list[str] = []
    for column_name in column_names:
        all_values = [float(d.get(column_name, 0)) for d in all_dicts]
        target_value = float(target_dict.get(column_name, 0))
        if not all_values:
            continue
        mean_value = sum(all_values) / len(all_values)
        std_value = (sum((v - mean_value) ** 2 for v in all_values) / len(all_values)) ** 0.5
        z_score_threshold = 2.0
        if std_value > 0 and abs(target_value - mean_value) / std_value > z_score_threshold:
            contributing.append(f"{column_name}={target_value:.0f} (mean={mean_value:.0f})")

    return contributing


def _build_heuristic_anomaly_results(
    feature_dicts: list[dict], column_names: list[str]
) -> list[AnomalyDetectionResult]:
    results: list[AnomalyDetectionResult] = []
    for feature_dict in feature_dicts:
        heuristic_score = _calculate_heuristic_anomaly_score(feature_dict)
        results.append(
            AnomalyDetectionResult(
                ip_address=feature_dict.get("ip_address", "unknown"),
                anomaly_score=heuristic_score,
                is_anomaly=heuristic_score >= ANOMALY_HIGH_THRESHOLD,
                contributing_features=_identify_contributing_features(
                    feature_dict, feature_dicts, column_names
                ),
            )
        )
    return results


def _calculate_heuristic_anomaly_score(feature_dict: dict) -> float:
    score = 0.0
    if feature_dict.get("critical_port_count", 0) > 0:
        score += 0.3
    if feature_dict.get("has_smb", 0) and feature_dict.get("has_rdp", 0):
        score += 0.2
    if feature_dict.get("has_db_exposed", 0):
        score += 0.2
    if feature_dict.get("cleartext_port_count", 0) > 1:
        score += 0.15
    if feature_dict.get("risky_port_contact_count", 0) > 5:
        score += 0.15
    return min(score, 1.0)
