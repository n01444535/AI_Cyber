import os
import pickle
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from backend.constants import (
    MIN_SAMPLES_TO_TRAIN,
    RANDOM_FOREST_MAX_DEPTH,
    RANDOM_FOREST_N_ESTIMATORS,
    TEST_SPLIT_RATIO,
)

CLASSIFIER_FEATURE_COLUMNS = [
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
    "bytes_sent",
    "bytes_received",
    "unique_destination_count",
    "syn_packet_count",
    "risky_port_contact_count",
]

RISK_CLASS_LABELS = ["Low", "Medium", "High", "Critical"]


class SuspiciousHostClassifier:
    def __init__(self) -> None:
        self._random_forest_model: RandomForestClassifier | None = None
        self._label_encoder: LabelEncoder | None = None
        self._is_trained: bool = False
        self._feature_importances: dict[str, float] = {}

    def train(self, labeled_host_features: list[dict]) -> dict:
        if len(labeled_host_features) < MIN_SAMPLES_TO_TRAIN:
            return {"status": "skipped", "reason": "insufficient training samples"}

        feature_matrix = _extract_feature_matrix(labeled_host_features)
        risk_labels = [sample.get("risk_label", "Low") for sample in labeled_host_features]

        self._label_encoder = LabelEncoder()
        encoded_labels = self._label_encoder.fit_transform(risk_labels)

        split_ratio = TEST_SPLIT_RATIO if len(labeled_host_features) > 10 else 0.0

        if split_ratio > 0:
            train_features, test_features, train_labels, test_labels = train_test_split(
                feature_matrix, encoded_labels, test_size=split_ratio, random_state=42
            )
        else:
            train_features = feature_matrix
            test_features = feature_matrix
            train_labels = encoded_labels
            test_labels = encoded_labels

        self._random_forest_model = RandomForestClassifier(
            n_estimators=RANDOM_FOREST_N_ESTIMATORS,
            max_depth=RANDOM_FOREST_MAX_DEPTH,
            random_state=42,
            class_weight="balanced",
        )
        self._random_forest_model.fit(train_features, train_labels)
        self._is_trained = True

        self._feature_importances = dict(
            zip(
                CLASSIFIER_FEATURE_COLUMNS,
                self._random_forest_model.feature_importances_.tolist(),
            )
        )

        test_accuracy = self._random_forest_model.score(test_features, test_labels)
        return {
            "status": "trained",
            "test_accuracy": round(test_accuracy, 4),
            "training_sample_count": len(train_features),
            "top_features": sorted(
                self._feature_importances.items(), key=lambda item: item[1], reverse=True
            )[:5],
        }

    def classify_hosts(self, host_feature_dicts: list[dict]) -> list[dict]:
        if not self._is_trained or not host_feature_dicts:
            return _build_heuristic_classifications(host_feature_dicts)

        feature_matrix = _extract_feature_matrix(host_feature_dicts)
        predicted_class_indices = self._random_forest_model.predict(feature_matrix)
        class_probabilities = self._random_forest_model.predict_proba(feature_matrix)
        decoded_labels = self._label_encoder.inverse_transform(predicted_class_indices)

        classification_results: list[dict] = []
        for index, feature_dict in enumerate(host_feature_dicts):
            max_probability = float(class_probabilities[index].max())
            classification_results.append(
                {
                    "ip_address": feature_dict.get("ip_address", "unknown"),
                    "predicted_risk_class": decoded_labels[index],
                    "confidence_score": max_probability,
                    "class_probabilities": dict(
                        zip(
                            self._label_encoder.classes_.tolist(),
                            class_probabilities[index].tolist(),
                        )
                    ),
                }
            )

        return classification_results

    def get_feature_importances(self) -> dict[str, float]:
        return dict(
            sorted(self._feature_importances.items(), key=lambda item: item[1], reverse=True)
        )

    def save_model(self, model_save_path: str) -> None:
        if not self._is_trained:
            return
        Path(model_save_path).mkdir(parents=True, exist_ok=True)
        model_file_path = os.path.join(model_save_path, "host_classifier.pkl")
        with open(model_file_path, "wb") as model_file:
            pickle.dump(
                {
                    "model": self._random_forest_model,
                    "label_encoder": self._label_encoder,
                    "feature_importances": self._feature_importances,
                },
                model_file,
            )

    def load_model(self, model_save_path: str) -> bool:
        model_file_path = os.path.join(model_save_path, "host_classifier.pkl")
        if not Path(model_file_path).exists():
            return False
        with open(model_file_path, "rb") as model_file:
            saved_data = pickle.load(model_file)
        self._random_forest_model = saved_data["model"]
        self._label_encoder = saved_data["label_encoder"]
        self._feature_importances = saved_data.get("feature_importances", {})
        self._is_trained = True
        return True


def _extract_feature_matrix(feature_dicts: list[dict]) -> np.ndarray:
    rows = []
    for feature_dict in feature_dicts:
        row = [float(feature_dict.get(col, 0)) for col in CLASSIFIER_FEATURE_COLUMNS]
        rows.append(row)
    return np.array(rows)


def _build_heuristic_classifications(host_feature_dicts: list[dict]) -> list[dict]:
    classification_results: list[dict] = []
    for feature_dict in host_feature_dicts:
        risk_class = _calculate_heuristic_risk_class(feature_dict)
        classification_results.append(
            {
                "ip_address": feature_dict.get("ip_address", "unknown"),
                "predicted_risk_class": risk_class,
                "confidence_score": 0.60,
                "class_probabilities": {},
            }
        )
    return classification_results


def _calculate_heuristic_risk_class(feature_dict: dict) -> str:
    critical_port_count = feature_dict.get("critical_port_count", 0)
    high_risk_port_count = feature_dict.get("high_risk_port_count", 0)
    has_smb = feature_dict.get("has_smb", 0)
    has_rdp = feature_dict.get("has_rdp", 0)
    has_db_exposed = feature_dict.get("has_db_exposed", 0)
    risky_port_contacts = feature_dict.get("risky_port_contact_count", 0)

    if critical_port_count >= 3 or (has_smb and has_rdp and has_db_exposed):
        return "Critical"
    if critical_port_count >= 1 or high_risk_port_count >= 5 or risky_port_contacts > 10:
        return "High"
    if high_risk_port_count >= 2 or risky_port_contacts > 3:
        return "Medium"
    return "Low"
