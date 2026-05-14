import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

from backend.correlation.engine import correlate_alerts_into_stories
from backend.ml.anomaly_detector import HostAnomalyDetector, TrafficAnomalyDetector
from backend.ml.host_classifier import SuspiciousHostClassifier
from backend.ml.traffic_clusterer import TrafficClusterer
from backend.models import ScanSessionResult
from backend.packet_analyzer.pcap_parser import parse_pcap_file
from backend.packet_analyzer.traffic_analyzer import (
    build_network_flows,
    detect_threats_in_traffic,
    extract_traffic_features_per_host,
)
from backend.reports.report_generator import generate_report
from backend.risk_engine import calculate_host_risk_profiles
from backend.scanners.nmap_parser import convert_hosts_to_feature_dicts, parse_nmap_xml_file
from backend.database import SessionRepository
from backend.threat_intel.ioc_lookup import IOCLookupService, extract_unique_external_ips

API_TITLE = "AI Cyber Fusion Platform API"
API_VERSION = "1.0.0"
API_DESCRIPTION = "Autonomous AI-Powered Threat Detection & Behavioral Security Analysis"

REPORTS_OUTPUT_DIR = "reports/"
MODELS_SAVE_DIR = "models/"
DB_FILE_PATH = "cyber_platform.db"

app = FastAPI(title=API_TITLE, version=API_VERSION, description=API_DESCRIPTION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_host_anomaly_detector = HostAnomalyDetector()
_traffic_anomaly_detector = TrafficAnomalyDetector()
_host_classifier = SuspiciousHostClassifier()
_traffic_clusterer = TrafficClusterer()
_ioc_service = IOCLookupService(cache_directory=".")
_session_repository = SessionRepository(DB_FILE_PATH)
_session_store: dict[str, ScanSessionResult] = {}


# ── Pydantic request/response models ──────────────────────────────────────────


class NmapAnalysisRequest(BaseModel):
    xml_file_path: str
    enable_ioc_lookup: bool = False


class NmapAnalysisResponse(BaseModel):
    session_id: str
    host_count: int
    alert_count: int
    critical_host_count: int
    top_risk_hosts: list[dict]
    attack_stories: list[dict]
    message: str


class IPExplainRequest(BaseModel):
    ip_address: str
    session_id: Optional[str] = None


class IPExplainResponse(BaseModel):
    ip_address: str
    risk_level: str
    risk_score: float
    ai_explanation: str
    threat_categories: list[str]
    mitre_techniques: list[str]
    correlated_story: str


class IOCLookupRequest(BaseModel):
    indicators: list[str]


class SessionSummaryResponse(BaseModel):
    session_id: str
    scan_timestamp: str
    total_hosts: int
    total_alerts: int
    overall_risk_score: float
    executive_summary: str


# ── Endpoints ──────────────────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
def read_root() -> str:
    return """
    <html><body style="font-family:monospace;background:#0f172a;color:#60a5fa;padding:40px">
    <h1>&#x1F6E1; AI Cyber Fusion Platform API</h1>
    <p style="color:#94a3b8">Autonomous Threat Detection &amp; Behavioral Security Analysis</p>
    <ul style="margin-top:20px;color:#e2e8f0;line-height:2">
      <li>POST /analyze/nmap &mdash; Analyze Nmap XML (server-side file path)</li>
      <li>POST /analyze/pcap &mdash; Analyze uploaded PCAP traffic file</li>
      <li>POST /analyze/full &mdash; Full analysis: upload both Nmap XML + PCAP</li>
      <li>POST /explain/ip &mdash; AI explanation for a specific host IP</li>
      <li>POST /ioc/lookup &mdash; IOC lookup via VirusTotal / AbuseIPDB</li>
      <li>GET  /sessions &mdash; List past scan sessions</li>
      <li>GET  /sessions/{id}/hosts &mdash; Host profiles for a session</li>
      <li>GET  /sessions/{id}/alerts &mdash; Threat alerts for a session</li>
      <li>GET  /sessions/{id}/stories &mdash; Attack stories for a session</li>
      <li>GET  /session/{id} &mdash; Session summary (in-memory)</li>
      <li>GET  /report/{id}/html &mdash; Download HTML report</li>
      <li>GET  /report/{id}/json &mdash; Download JSON report</li>
      <li>GET  /hosts/{ip}/history &mdash; Session history for an IP</li>
      <li>DELETE /sessions/{id} &mdash; Delete a session record</li>
      <li>GET  /health &mdash; Health check</li>
    </ul>
    <p style="margin-top:20px"><a href="/docs" style="color:#60a5fa">&#x1F4D6; Interactive API Docs &#x2192;</a></p>
    </body></html>
    """


@app.get("/health")
def check_health() -> dict:
    return {"status": "ok", "platform": API_TITLE, "version": API_VERSION}


@app.post("/analyze/nmap", response_model=NmapAnalysisResponse)
def analyze_nmap_scan(request: NmapAnalysisRequest) -> NmapAnalysisResponse:
    if not Path(request.xml_file_path).exists():
        raise HTTPException(
            status_code=404, detail=f"Nmap XML file not found: {request.xml_file_path}"
        )

    session_id = str(uuid.uuid4())[:12]
    scan_timestamp = datetime.now(timezone.utc).isoformat()

    scanned_hosts = parse_nmap_xml_file(request.xml_file_path)
    if not scanned_hosts:
        raise HTTPException(status_code=400, detail="No live hosts found in Nmap XML file.")

    host_feature_dicts = convert_hosts_to_feature_dicts(scanned_hosts)
    anomaly_results = _host_anomaly_detector.detect_anomalies(host_feature_dicts)
    _host_anomaly_detector.train(host_feature_dicts)
    anomaly_results = _host_anomaly_detector.detect_anomalies(host_feature_dicts)

    ioc_results = []
    if request.enable_ioc_lookup:
        external_ips = extract_unique_external_ips(host_feature_dicts)
        ioc_results = _ioc_service.lookup_indicators_in_bulk(external_ips[:20])

    attack_stories = correlate_alerts_into_stories([])
    host_profiles = calculate_host_risk_profiles(
        scanned_hosts=scanned_hosts,
        threat_alerts=[],
        anomaly_results=anomaly_results,
        ioc_results=ioc_results,
        attack_stories=attack_stories,
    )

    executive_summary = _compose_executive_summary(host_profiles, [], attack_stories)

    session_result = ScanSessionResult(
        session_id=session_id,
        scan_timestamp=scan_timestamp,
        scanned_hosts=scanned_hosts,
        threat_alerts=[],
        host_risk_profiles=host_profiles,
        attack_stories=attack_stories,
        timeline_events=[],
        total_risk_score=max((p.risk_score for p in host_profiles), default=0.0),
        executive_summary=executive_summary,
        nmap_file_path=request.xml_file_path,
    )
    _session_store[session_id] = session_result
    _session_repository.save_session(session_result)

    critical_hosts = [p for p in host_profiles if p.risk_level.value == "Critical"]
    return NmapAnalysisResponse(
        session_id=session_id,
        host_count=len(scanned_hosts),
        alert_count=0,
        critical_host_count=len(critical_hosts),
        top_risk_hosts=[
            {
                "ip": p.ip_address,
                "hostname": p.hostname,
                "risk_level": p.risk_level.value,
                "score": p.risk_score,
                "explanation": p.ai_explanation,
            }
            for p in host_profiles[:5]
        ],
        attack_stories=[],
        message=f"Analyzed {len(scanned_hosts)} hosts. {len(critical_hosts)} critical risk hosts found.",
    )


@app.post("/analyze/pcap")
async def analyze_pcap_traffic(pcap_file: UploadFile = File(...)) -> dict:
    import tempfile

    session_id = str(uuid.uuid4())[:12]
    scan_timestamp = datetime.now(timezone.utc).isoformat()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as temp_pcap_file:
        temp_pcap_path = temp_pcap_file.name
        content = await pcap_file.read()
        temp_pcap_file.write(content)

    try:
        packet_records = parse_pcap_file(temp_pcap_path)
        if not packet_records:
            raise HTTPException(status_code=400, detail="No packets parsed from PCAP file.")

        network_flows = build_network_flows(packet_records)
        threat_alerts = detect_threats_in_traffic(packet_records, network_flows)
        traffic_features = extract_traffic_features_per_host(packet_records, network_flows)

        _traffic_anomaly_detector.train(traffic_features)
        anomaly_results = _traffic_anomaly_detector.detect_anomalies(traffic_features)

        attack_stories = correlate_alerts_into_stories(threat_alerts)

        ioc_results = []
        external_ips = extract_unique_external_ips(traffic_features)
        if external_ips:
            ioc_results = _ioc_service.lookup_indicators_in_bulk(external_ips[:10])

        host_profiles = calculate_host_risk_profiles(
            scanned_hosts=[],
            threat_alerts=threat_alerts,
            anomaly_results=anomaly_results,
            ioc_results=ioc_results,
            attack_stories=attack_stories,
        )

        all_timeline_events = []
        for story in attack_stories:
            all_timeline_events.extend(story.timeline_events)

        executive_summary = _compose_executive_summary(host_profiles, threat_alerts, attack_stories)

        session_result = ScanSessionResult(
            session_id=session_id,
            scan_timestamp=scan_timestamp,
            scanned_hosts=[],
            threat_alerts=threat_alerts,
            host_risk_profiles=host_profiles,
            attack_stories=attack_stories,
            timeline_events=all_timeline_events,
            total_risk_score=max((p.risk_score for p in host_profiles), default=0.0),
            executive_summary=executive_summary,
            pcap_file_path=pcap_file.filename,
        )
        _session_store[session_id] = session_result
        _session_repository.save_session(session_result)

        return {
            "session_id": session_id,
            "packet_count": len(packet_records),
            "flow_count": len(network_flows),
            "alert_count": len(threat_alerts),
            "anomaly_count": sum(1 for r in anomaly_results if r.is_anomaly),
            "attack_story_count": len(attack_stories),
            "critical_host_count": sum(
                1 for p in host_profiles if p.risk_level.value == "Critical"
            ),
            "top_alerts": [
                {
                    "category": a.threat_category.value,
                    "source": a.source_ip,
                    "risk": a.risk_level.value,
                    "description": a.description[:150],
                }
                for a in sorted(threat_alerts, key=lambda x: x.confidence_score, reverse=True)[:5]
            ],
            "message": f"Analyzed {len(packet_records)} packets. {len(threat_alerts)} threats detected.",
        }
    finally:
        Path(temp_pcap_path).unlink(missing_ok=True)


@app.post("/analyze/full")
async def analyze_full(
    nmap_file: UploadFile = File(..., description="Nmap XML scan output file"),
    pcap_file: UploadFile = File(..., description="PCAP or PCAPNG traffic file"),
    enable_ioc: bool = Form(False),
) -> dict:
    import tempfile

    session_id = str(uuid.uuid4())[:12]
    scan_timestamp = datetime.now(timezone.utc).isoformat()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp_nmap:
        tmp_nmap_path = tmp_nmap.name
        tmp_nmap.write(await nmap_file.read())

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp_pcap:
        tmp_pcap_path = tmp_pcap.name
        tmp_pcap.write(await pcap_file.read())

    try:
        scanned_hosts = parse_nmap_xml_file(tmp_nmap_path)
        packet_records = parse_pcap_file(tmp_pcap_path)

        if not scanned_hosts and not packet_records:
            raise HTTPException(status_code=400, detail="Both files produced no usable data.")

        network_flows = build_network_flows(packet_records)
        threat_alerts = detect_threats_in_traffic(packet_records, network_flows)

        host_scan_features = convert_hosts_to_feature_dicts(scanned_hosts)
        traffic_features = extract_traffic_features_per_host(packet_records, network_flows)

        _host_anomaly_detector.train(host_scan_features)
        _traffic_anomaly_detector.train(traffic_features)
        host_anomaly_results = _host_anomaly_detector.detect_anomalies(host_scan_features)
        traffic_anomaly_results = _traffic_anomaly_detector.detect_anomalies(traffic_features)
        all_anomaly_results = host_anomaly_results + traffic_anomaly_results

        ioc_results = []
        if enable_ioc:
            external_ips = extract_unique_external_ips(traffic_features)
            if external_ips:
                ioc_results = _ioc_service.lookup_indicators_in_bulk(external_ips[:20])

        attack_stories = correlate_alerts_into_stories(threat_alerts)
        host_profiles = calculate_host_risk_profiles(
            scanned_hosts=scanned_hosts,
            threat_alerts=threat_alerts,
            anomaly_results=all_anomaly_results,
            ioc_results=ioc_results,
            attack_stories=attack_stories,
        )

        all_timeline_events = [
            event for story in attack_stories for event in story.timeline_events
        ]
        executive_summary = _compose_executive_summary(host_profiles, threat_alerts, attack_stories)

        session_result = ScanSessionResult(
            session_id=session_id,
            scan_timestamp=scan_timestamp,
            scanned_hosts=scanned_hosts,
            threat_alerts=threat_alerts,
            host_risk_profiles=host_profiles,
            attack_stories=attack_stories,
            timeline_events=all_timeline_events,
            total_risk_score=max((p.risk_score for p in host_profiles), default=0.0),
            executive_summary=executive_summary,
            nmap_file_path=nmap_file.filename,
            pcap_file_path=pcap_file.filename,
        )
        _session_store[session_id] = session_result
        _session_repository.save_session(session_result)

        return {
            "session_id": session_id,
            "host_count": len(scanned_hosts),
            "packet_count": len(packet_records),
            "flow_count": len(network_flows),
            "alert_count": len(threat_alerts),
            "attack_story_count": len(attack_stories),
            "critical_host_count": sum(
                1 for p in host_profiles if p.risk_level.value == "Critical"
            ),
            "overall_risk_score": session_result.total_risk_score,
            "executive_summary": executive_summary,
            "message": (
                f"Full analysis complete: {len(scanned_hosts)} hosts, "
                f"{len(packet_records)} packets, {len(threat_alerts)} alerts."
            ),
        }
    finally:
        Path(tmp_nmap_path).unlink(missing_ok=True)
        Path(tmp_pcap_path).unlink(missing_ok=True)


@app.delete("/sessions/{session_id}")
def delete_session(session_id: str) -> dict:
    """Remove a session and all its child records from the database."""
    _session_store.pop(session_id, None)
    deleted = _session_repository.delete_session(session_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found.")
    return {"deleted": True, "session_id": session_id}


@app.post("/explain/ip", response_model=IPExplainResponse)
def explain_host_risk(request: IPExplainRequest) -> IPExplainResponse:
    if request.session_id and request.session_id in _session_store:
        session = _session_store[request.session_id]
        for profile in session.host_risk_profiles:
            if profile.ip_address == request.ip_address:
                return IPExplainResponse(
                    ip_address=profile.ip_address,
                    risk_level=profile.risk_level.value,
                    risk_score=profile.risk_score,
                    ai_explanation=profile.ai_explanation,
                    threat_categories=[a.threat_category.value for a in profile.threat_alerts],
                    mitre_techniques=profile.mitre_techniques,
                    correlated_story=profile.correlated_story,
                )

    raise HTTPException(
        status_code=404,
        detail=f"Host {request.ip_address} not found in session. Run an analysis first.",
    )


@app.post("/ioc/lookup")
def lookup_ioc_indicators(request: IOCLookupRequest) -> dict:
    if not request.indicators:
        raise HTTPException(status_code=400, detail="No indicators provided.")
    if len(request.indicators) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 indicators per request.")

    lookup_results = _ioc_service.lookup_indicators_in_bulk(request.indicators)
    malicious_results = [r for r in lookup_results if r.is_malicious]

    return {
        "total_checked": len(lookup_results),
        "malicious_count": len(malicious_results),
        "results": [
            {
                "indicator": r.indicator,
                "type": r.indicator_type,
                "is_malicious": r.is_malicious,
                "virustotal_positives": r.virustotal_positives,
                "abuseipdb_score": r.abuseipdb_confidence_score,
                "otx_pulses": r.otx_pulse_count,
            }
            for r in lookup_results
        ],
    }


@app.get("/session/{session_id}", response_model=SessionSummaryResponse)
def get_session_summary(session_id: str) -> SessionSummaryResponse:
    session = _session_store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found.")
    return SessionSummaryResponse(
        session_id=session.session_id,
        scan_timestamp=session.scan_timestamp,
        total_hosts=len(session.scanned_hosts) or len(session.host_risk_profiles),
        total_alerts=len(session.threat_alerts),
        overall_risk_score=session.total_risk_score,
        executive_summary=session.executive_summary,
    )


@app.get("/report/{session_id}/html")
def download_html_report(session_id: str, background_tasks: BackgroundTasks) -> FileResponse:
    session = _session_store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found.")

    report_file_paths = generate_report(session, REPORTS_OUTPUT_DIR)
    _session_repository.update_report_paths(
        session_id,
        json_report_path=report_file_paths["json"],
        html_report_path=report_file_paths["html"],
    )

    return FileResponse(
        path=report_file_paths["html"],
        filename=f"cyber_report_{session_id}.html",
        media_type="text/html",
    )


@app.get("/report/{session_id}/json")
def download_json_report(session_id: str) -> FileResponse:
    session = _session_store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found.")

    report_file_paths = generate_report(session, REPORTS_OUTPUT_DIR)
    _session_repository.update_report_paths(
        session_id,
        json_report_path=report_file_paths["json"],
        html_report_path=report_file_paths["html"],
    )

    return FileResponse(
        path=report_file_paths["json"],
        filename=f"cyber_report_{session_id}.json",
        media_type="application/json",
    )


@app.get("/sessions")
def list_all_sessions(limit: int = 50) -> dict:
    """Return a paginated list of past scan sessions from the database."""
    session_summaries = _session_repository.list_sessions(limit=limit)
    return {
        "total": _session_repository.count_sessions(),
        "sessions": session_summaries,
    }


@app.get("/sessions/{session_id}/hosts")
def get_session_hosts(session_id: str) -> dict:
    summary = _session_repository.get_session_summary(session_id)
    if not summary:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found in database.")
    host_profiles = _session_repository.get_host_profiles_for_session(session_id)
    return {"session_id": session_id, "host_count": len(host_profiles), "hosts": host_profiles}


@app.get("/sessions/{session_id}/alerts")
def get_session_alerts(session_id: str) -> dict:
    summary = _session_repository.get_session_summary(session_id)
    if not summary:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found in database.")
    alerts = _session_repository.get_alerts_for_session(session_id)
    return {"session_id": session_id, "alert_count": len(alerts), "alerts": alerts}


@app.get("/sessions/{session_id}/stories")
def get_session_stories(session_id: str) -> dict:
    summary = _session_repository.get_session_summary(session_id)
    if not summary:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found in database.")
    stories = _session_repository.get_stories_for_session(session_id)
    return {"session_id": session_id, "story_count": len(stories), "stories": stories}


@app.get("/hosts/{ip_address}/history")
def get_host_history(ip_address: str) -> dict:
    """Return all past sessions that include a specific host IP."""
    past_sessions = _session_repository.find_sessions_by_ip(ip_address)
    return {
        "ip_address": ip_address,
        "session_count": len(past_sessions),
        "sessions": past_sessions,
    }


def _compose_executive_summary(host_profiles, threat_alerts, attack_stories) -> str:
    from backend.models import RiskLevel

    critical_count = sum(1 for p in host_profiles if p.risk_level == RiskLevel.CRITICAL)
    high_count = sum(1 for p in host_profiles if p.risk_level == RiskLevel.HIGH)
    alert_count = len(threat_alerts)
    story_count = len(attack_stories)

    if critical_count == 0 and alert_count == 0:
        return "No significant threats detected. Network appears within normal parameters."

    parts = []
    if critical_count > 0:
        parts.append(f"{critical_count} critical-risk host(s) require immediate attention.")
    if high_count > 0:
        parts.append(f"{high_count} high-risk host(s) identified.")
    if alert_count > 0:
        parts.append(f"{alert_count} threat alert(s) generated.")
    if story_count > 0:
        parts.append(
            f"{story_count} correlated attack story(ies) detected — possible coordinated attack campaign."
        )

    return " ".join(parts)
