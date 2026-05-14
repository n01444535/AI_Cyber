"""
SQLite persistence layer for scan sessions, host risk profiles, threat alerts,
and correlated attack stories.

All JSON columns store lists/dicts serialized with json.dumps/loads so no extra
ORM dependency is needed — only the stdlib sqlite3 module.
"""

import json
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from backend.models import (
    ScanSessionResult,
)

DEFAULT_DB_PATH = "cyber_platform.db"

_CREATE_SESSIONS_TABLE = """
CREATE TABLE IF NOT EXISTS scan_sessions (
    session_id          TEXT    PRIMARY KEY,
    scan_timestamp      TEXT    NOT NULL,
    nmap_file_path      TEXT,
    pcap_file_path      TEXT,
    total_risk_score    REAL    NOT NULL DEFAULT 0.0,
    executive_summary   TEXT    NOT NULL DEFAULT '',
    host_count          INTEGER NOT NULL DEFAULT 0,
    alert_count         INTEGER NOT NULL DEFAULT 0,
    story_count         INTEGER NOT NULL DEFAULT 0,
    json_report_path    TEXT,
    html_report_path    TEXT,
    created_at          TEXT    NOT NULL
)
"""

_CREATE_HOST_PROFILES_TABLE = """
CREATE TABLE IF NOT EXISTS host_risk_profiles (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id          TEXT    NOT NULL REFERENCES scan_sessions(session_id),
    ip_address          TEXT    NOT NULL,
    hostname            TEXT    NOT NULL DEFAULT '',
    risk_level          TEXT    NOT NULL,
    risk_score          REAL    NOT NULL DEFAULT 0.0,
    open_port_count     INTEGER NOT NULL DEFAULT 0,
    critical_port_count INTEGER NOT NULL DEFAULT 0,
    anomaly_score       REAL    NOT NULL DEFAULT 0.0,
    is_ml_anomaly       INTEGER NOT NULL DEFAULT 0,
    ai_explanation      TEXT    NOT NULL DEFAULT '',
    mitre_techniques    TEXT    NOT NULL DEFAULT '[]',
    correlated_story    TEXT    NOT NULL DEFAULT ''
)
"""

_CREATE_THREAT_ALERTS_TABLE = """
CREATE TABLE IF NOT EXISTS threat_alerts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id          TEXT    NOT NULL REFERENCES scan_sessions(session_id),
    alert_id            TEXT    NOT NULL,
    source_ip           TEXT    NOT NULL,
    destination_ip      TEXT    NOT NULL DEFAULT '',
    threat_category     TEXT    NOT NULL,
    risk_level          TEXT    NOT NULL,
    confidence_score    REAL    NOT NULL DEFAULT 0.0,
    description         TEXT    NOT NULL DEFAULT '',
    mitre_technique_id  TEXT    NOT NULL DEFAULT '',
    mitre_technique_name TEXT   NOT NULL DEFAULT '',
    mitre_tactic_id     TEXT    NOT NULL DEFAULT '',
    mitre_tactic_name   TEXT    NOT NULL DEFAULT '',
    timestamp           TEXT    NOT NULL DEFAULT '',
    evidence            TEXT    NOT NULL DEFAULT '[]',
    possible_false_positive TEXT NOT NULL DEFAULT '[]',
    recommended_actions TEXT    NOT NULL DEFAULT '[]'
)
"""

_CREATE_ATTACK_STORIES_TABLE = """
CREATE TABLE IF NOT EXISTS attack_stories (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id          TEXT    NOT NULL REFERENCES scan_sessions(session_id),
    story_id            TEXT    NOT NULL,
    attack_narrative    TEXT    NOT NULL DEFAULT '',
    overall_risk_score  REAL    NOT NULL DEFAULT 0.0,
    risk_level          TEXT    NOT NULL,
    involved_ips        TEXT    NOT NULL DEFAULT '[]',
    mitre_tactics       TEXT    NOT NULL DEFAULT '[]',
    mitre_techniques    TEXT    NOT NULL DEFAULT '[]',
    first_seen          TEXT    NOT NULL DEFAULT '',
    last_seen           TEXT    NOT NULL DEFAULT '',
    ai_explanation      TEXT    NOT NULL DEFAULT ''
)
"""

_INDEX_STATEMENTS = [
    "CREATE INDEX IF NOT EXISTS idx_host_profiles_session ON host_risk_profiles(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_session        ON threat_alerts(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_stories_session       ON attack_stories(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_host_profiles_ip      ON host_risk_profiles(ip_address)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_source_ip      ON threat_alerts(source_ip)",
]


class SessionRepository:
    """CRUD interface for all scan-session related tables."""

    def __init__(self, db_file_path: str = DEFAULT_DB_PATH) -> None:
        self._db_file_path = db_file_path
        self._initialize_schema()

    # ── private helpers ────────────────────────────────────────────────────────

    def _open_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._db_file_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    _ALERT_MIGRATIONS = [
        "ALTER TABLE threat_alerts ADD COLUMN possible_false_positive TEXT NOT NULL DEFAULT '[]'",
        "ALTER TABLE threat_alerts ADD COLUMN recommended_actions TEXT NOT NULL DEFAULT '[]'",
    ]

    def _initialize_schema(self) -> None:
        with self._open_connection() as connection:
            connection.execute(_CREATE_SESSIONS_TABLE)
            connection.execute(_CREATE_HOST_PROFILES_TABLE)
            connection.execute(_CREATE_THREAT_ALERTS_TABLE)
            connection.execute(_CREATE_ATTACK_STORIES_TABLE)
            for index_statement in _INDEX_STATEMENTS:
                connection.execute(index_statement)
            for migration_sql in self._ALERT_MIGRATIONS:
                try:
                    connection.execute(migration_sql)
                except sqlite3.OperationalError:
                    pass  # Column already exists — safe to skip

    # ── save ───────────────────────────────────────────────────────────────────

    def save_session(
        self,
        session: ScanSessionResult,
        json_report_path: Optional[str] = None,
        html_report_path: Optional[str] = None,
    ) -> None:
        """Persist a full ScanSessionResult and all its child records."""
        created_at = datetime.now(timezone.utc).isoformat()

        with self._open_connection() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO scan_sessions
                    (session_id, scan_timestamp, nmap_file_path, pcap_file_path,
                     total_risk_score, executive_summary, host_count, alert_count,
                     story_count, json_report_path, html_report_path, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.session_id,
                    session.scan_timestamp,
                    session.nmap_file_path,
                    session.pcap_file_path,
                    session.total_risk_score,
                    session.executive_summary,
                    len(session.scanned_hosts) or len(session.host_risk_profiles),
                    len(session.threat_alerts),
                    len(session.attack_stories),
                    json_report_path,
                    html_report_path,
                    created_at,
                ),
            )

            connection.execute(
                "DELETE FROM host_risk_profiles WHERE session_id = ?",
                (session.session_id,),
            )
            for profile in session.host_risk_profiles:
                connection.execute(
                    """
                    INSERT INTO host_risk_profiles
                        (session_id, ip_address, hostname, risk_level, risk_score,
                         open_port_count, critical_port_count, anomaly_score,
                         is_ml_anomaly, ai_explanation, mitre_techniques, correlated_story)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session.session_id,
                        profile.ip_address,
                        profile.hostname or "",
                        profile.risk_level.value,
                        profile.risk_score,
                        profile.open_port_count,
                        profile.critical_port_count,
                        profile.anomaly_score,
                        int(profile.is_ml_anomaly),
                        profile.ai_explanation,
                        json.dumps(profile.mitre_techniques),
                        profile.correlated_story,
                    ),
                )

            connection.execute(
                "DELETE FROM threat_alerts WHERE session_id = ?",
                (session.session_id,),
            )
            for alert in session.threat_alerts:
                connection.execute(
                    """
                    INSERT INTO threat_alerts
                        (session_id, alert_id, source_ip, destination_ip, threat_category,
                         risk_level, confidence_score, description, mitre_technique_id,
                         mitre_technique_name, mitre_tactic_id, mitre_tactic_name,
                         timestamp, evidence, possible_false_positive, recommended_actions)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session.session_id,
                        alert.alert_id,
                        alert.source_ip,
                        alert.destination_ip,
                        alert.threat_category.value,
                        alert.risk_level.value,
                        alert.confidence_score,
                        alert.description,
                        alert.mitre_technique_id,
                        alert.mitre_technique_name,
                        alert.mitre_tactic_id,
                        alert.mitre_tactic_name,
                        alert.timestamp,
                        json.dumps(alert.evidence),
                        json.dumps(alert.possible_false_positive),
                        json.dumps(alert.recommended_actions),
                    ),
                )

            connection.execute(
                "DELETE FROM attack_stories WHERE session_id = ?",
                (session.session_id,),
            )
            for story in session.attack_stories:
                connection.execute(
                    """
                    INSERT INTO attack_stories
                        (session_id, story_id, attack_narrative, overall_risk_score,
                         risk_level, involved_ips, mitre_tactics, mitre_techniques,
                         first_seen, last_seen, ai_explanation)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session.session_id,
                        story.story_id,
                        story.attack_narrative,
                        story.overall_risk_score,
                        story.risk_level.value,
                        json.dumps(story.involved_ip_addresses),
                        json.dumps(story.mitre_tactics),
                        json.dumps(story.mitre_techniques),
                        story.first_seen,
                        story.last_seen,
                        story.ai_explanation,
                    ),
                )

    def update_report_paths(
        self,
        session_id: str,
        json_report_path: str,
        html_report_path: str,
    ) -> None:
        with self._open_connection() as connection:
            connection.execute(
                """
                UPDATE scan_sessions
                SET json_report_path = ?, html_report_path = ?
                WHERE session_id = ?
                """,
                (json_report_path, html_report_path, session_id),
            )

    # ── query ──────────────────────────────────────────────────────────────────

    def list_sessions(self, limit: int = 50) -> list[dict]:
        """Return lightweight session summaries, newest first."""
        with self._open_connection() as connection:
            rows = connection.execute(
                """
                SELECT session_id, scan_timestamp, nmap_file_path, pcap_file_path,
                       total_risk_score, executive_summary, host_count, alert_count,
                       story_count, json_report_path, html_report_path, created_at
                FROM scan_sessions
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_session_summary(self, session_id: str) -> Optional[dict]:
        with self._open_connection() as connection:
            row = connection.execute(
                "SELECT * FROM scan_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_host_profiles_for_session(self, session_id: str) -> list[dict]:
        with self._open_connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM host_risk_profiles
                WHERE session_id = ?
                ORDER BY risk_score DESC
                """,
                (session_id,),
            ).fetchall()
        result = []
        for row in rows:
            record = dict(row)
            record["mitre_techniques"] = json.loads(record["mitre_techniques"])
            record["is_ml_anomaly"] = bool(record["is_ml_anomaly"])
            result.append(record)
        return result

    def get_alerts_for_session(self, session_id: str) -> list[dict]:
        with self._open_connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM threat_alerts
                WHERE session_id = ?
                ORDER BY confidence_score DESC
                """,
                (session_id,),
            ).fetchall()
        result = []
        for row in rows:
            record = dict(row)
            record["evidence"] = json.loads(record["evidence"])
            record["possible_false_positive"] = json.loads(record.get("possible_false_positive", "[]"))
            record["recommended_actions"] = json.loads(record.get("recommended_actions", "[]"))
            result.append(record)
        return result

    def get_stories_for_session(self, session_id: str) -> list[dict]:
        with self._open_connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM attack_stories
                WHERE session_id = ?
                ORDER BY overall_risk_score DESC
                """,
                (session_id,),
            ).fetchall()
        result = []
        for row in rows:
            record = dict(row)
            record["involved_ips"] = json.loads(record["involved_ips"])
            record["mitre_tactics"] = json.loads(record["mitre_tactics"])
            record["mitre_techniques"] = json.loads(record["mitre_techniques"])
            result.append(record)
        return result

    def find_sessions_by_ip(self, ip_address: str) -> list[dict]:
        """Return all sessions that contain a specific host IP."""
        with self._open_connection() as connection:
            rows = connection.execute(
                """
                SELECT DISTINCT s.session_id, s.scan_timestamp, s.total_risk_score,
                       s.executive_summary, h.risk_level, h.risk_score, h.ai_explanation
                FROM scan_sessions s
                JOIN host_risk_profiles h ON h.session_id = s.session_id
                WHERE h.ip_address = ?
                ORDER BY s.created_at DESC
                """,
                (ip_address,),
            ).fetchall()
        return [dict(row) for row in rows]

    def count_sessions(self) -> int:
        with self._open_connection() as connection:
            row = connection.execute("SELECT COUNT(*) FROM scan_sessions").fetchone()
        return row[0]

    def delete_session(self, session_id: str) -> bool:
        """Delete a session and all its child records. Returns True if found."""
        with self._open_connection() as connection:
            result = connection.execute(
                "DELETE FROM scan_sessions WHERE session_id = ?",
                (session_id,),
            )
        return result.rowcount > 0
