import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

from backend.constants import (
    ABUSEIPDB_CONFIDENCE_THRESHOLD,
    IOC_CACHE_TTL_HOURS,
    VIRUSTOTAL_MALICIOUS_MIN_VOTES,
)
from backend.models import IOCLookupResult

VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
VIRUSTOTAL_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{indicator}"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
OTX_IP_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general"
OTX_DOMAIN_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/general"
MITRE_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

REQUEST_TIMEOUT_SECONDS = 10
CACHE_FILE_NAME = ".ioc_cache.json"


class IOCLookupService:
    def __init__(self, cache_directory: str = ".") -> None:
        self._virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")
        self._abuseipdb_api_key: str = os.getenv("ABUSEIPDB_API_KEY", "")
        self._otx_api_key: str = os.getenv("OTX_API_KEY", "")
        self._cache_file_path: str = os.path.join(cache_directory, CACHE_FILE_NAME)
        self._in_memory_cache: dict = self._load_cache_from_disk()

    def lookup_ip(self, ip_address: str) -> IOCLookupResult:
        cached_result = self._get_from_cache(ip_address)
        if cached_result:
            return cached_result

        virustotal_result = self._query_virustotal_ip(ip_address)
        abuseipdb_result = self._query_abuseipdb(ip_address)
        otx_result = self._query_otx_ip(ip_address)

        vt_positives = virustotal_result.get("malicious_count", 0)
        vt_total = virustotal_result.get("total_scanners", 0)
        abuse_score = abuseipdb_result.get("confidence_score", 0)
        otx_pulses = otx_result.get("pulse_count", 0)

        is_malicious = (
            vt_positives >= VIRUSTOTAL_MALICIOUS_MIN_VOTES
            or abuse_score >= ABUSEIPDB_CONFIDENCE_THRESHOLD
            or otx_pulses >= 1
        )

        lookup_result = IOCLookupResult(
            indicator=ip_address,
            indicator_type="ip",
            is_malicious=is_malicious,
            virustotal_positives=vt_positives,
            virustotal_total_scanners=vt_total,
            abuseipdb_confidence_score=abuse_score,
            otx_pulse_count=otx_pulses,
            last_analysis_timestamp=datetime.now(timezone.utc).isoformat(),
            error_message=virustotal_result.get("error", ""),
        )

        self._store_in_cache(ip_address, lookup_result)
        return lookup_result

    def lookup_domain(self, domain_name: str) -> IOCLookupResult:
        cached_result = self._get_from_cache(domain_name)
        if cached_result:
            return cached_result

        virustotal_result = self._query_virustotal_domain(domain_name)
        otx_result = self._query_otx_domain(domain_name)

        vt_positives = virustotal_result.get("malicious_count", 0)
        vt_total = virustotal_result.get("total_scanners", 0)
        otx_pulses = otx_result.get("pulse_count", 0)

        is_malicious = vt_positives >= VIRUSTOTAL_MALICIOUS_MIN_VOTES or otx_pulses >= 1

        lookup_result = IOCLookupResult(
            indicator=domain_name,
            indicator_type="domain",
            is_malicious=is_malicious,
            virustotal_positives=vt_positives,
            virustotal_total_scanners=vt_total,
            abuseipdb_confidence_score=0,
            otx_pulse_count=otx_pulses,
            last_analysis_timestamp=datetime.now(timezone.utc).isoformat(),
            error_message=virustotal_result.get("error", ""),
        )

        self._store_in_cache(domain_name, lookup_result)
        return lookup_result

    def lookup_indicators_in_bulk(self, indicators: list[str]) -> list[IOCLookupResult]:
        results: list[IOCLookupResult] = []
        for indicator in indicators:
            if _looks_like_ip_address(indicator):
                results.append(self.lookup_ip(indicator))
            else:
                results.append(self.lookup_domain(indicator))
            time.sleep(0.2)  # avoid rate limiting
        return results

    def _query_virustotal_ip(self, ip_address: str) -> dict:
        if not self._virustotal_api_key:
            return {"error": "No VirusTotal API key configured"}
        try:
            response = requests.get(
                VIRUSTOTAL_IP_URL.format(indicator=ip_address),
                headers={"x-apikey": self._virustotal_api_key},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if response.status_code != 200:
                return {"error": f"VirusTotal HTTP {response.status_code}"}
            response_data = response.json()
            stats = (
                response_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            )
            return {
                "malicious_count": stats.get("malicious", 0),
                "total_scanners": sum(stats.values()),
            }
        except Exception as request_error:
            return {"error": str(request_error)}

    def _query_virustotal_domain(self, domain_name: str) -> dict:
        if not self._virustotal_api_key:
            return {"error": "No VirusTotal API key configured"}
        try:
            response = requests.get(
                VIRUSTOTAL_DOMAIN_URL.format(indicator=domain_name),
                headers={"x-apikey": self._virustotal_api_key},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if response.status_code != 200:
                return {"error": f"VirusTotal HTTP {response.status_code}"}
            response_data = response.json()
            stats = (
                response_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            )
            return {
                "malicious_count": stats.get("malicious", 0),
                "total_scanners": sum(stats.values()),
            }
        except Exception as request_error:
            return {"error": str(request_error)}

    def _query_abuseipdb(self, ip_address: str) -> dict:
        if not self._abuseipdb_api_key:
            return {"confidence_score": 0}
        try:
            response = requests.get(
                ABUSEIPDB_URL,
                params={"ipAddress": ip_address, "maxAgeInDays": "90"},
                headers={"Key": self._abuseipdb_api_key, "Accept": "application/json"},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if response.status_code != 200:
                return {"confidence_score": 0}
            response_data = response.json()
            abuse_confidence = response_data.get("data", {}).get("abuseConfidenceScore", 0)
            return {"confidence_score": abuse_confidence}
        except Exception:
            return {"confidence_score": 0}

    def _query_otx_ip(self, ip_address: str) -> dict:
        if not self._otx_api_key:
            return {"pulse_count": 0}
        try:
            response = requests.get(
                OTX_IP_URL.format(indicator=ip_address),
                headers={"X-OTX-API-KEY": self._otx_api_key},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if response.status_code != 200:
                return {"pulse_count": 0}
            response_data = response.json()
            pulse_count = response_data.get("pulse_info", {}).get("count", 0)
            return {"pulse_count": pulse_count}
        except Exception:
            return {"pulse_count": 0}

    def _query_otx_domain(self, domain_name: str) -> dict:
        if not self._otx_api_key:
            return {"pulse_count": 0}
        try:
            response = requests.get(
                OTX_DOMAIN_URL.format(indicator=domain_name),
                headers={"X-OTX-API-KEY": self._otx_api_key},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if response.status_code != 200:
                return {"pulse_count": 0}
            response_data = response.json()
            pulse_count = response_data.get("pulse_info", {}).get("count", 0)
            return {"pulse_count": pulse_count}
        except Exception:
            return {"pulse_count": 0}

    def _get_from_cache(self, indicator: str) -> IOCLookupResult | None:
        cached_entry = self._in_memory_cache.get(indicator)
        if not cached_entry:
            return None
        cache_age_hours = (time.time() - cached_entry["cached_at"]) / 3600
        if cache_age_hours > IOC_CACHE_TTL_HOURS:
            del self._in_memory_cache[indicator]
            return None
        cached_data = cached_entry["data"]
        return IOCLookupResult(**cached_data)

    def _store_in_cache(self, indicator: str, result: IOCLookupResult) -> None:
        self._in_memory_cache[indicator] = {
            "cached_at": time.time(),
            "data": {
                "indicator": result.indicator,
                "indicator_type": result.indicator_type,
                "is_malicious": result.is_malicious,
                "virustotal_positives": result.virustotal_positives,
                "virustotal_total_scanners": result.virustotal_total_scanners,
                "abuseipdb_confidence_score": result.abuseipdb_confidence_score,
                "otx_pulse_count": result.otx_pulse_count,
                "last_analysis_timestamp": result.last_analysis_timestamp,
                "error_message": result.error_message,
            },
        }
        self._persist_cache_to_disk()

    def _load_cache_from_disk(self) -> dict:
        if not Path(self._cache_file_path).exists():
            return {}
        try:
            with open(self._cache_file_path) as cache_file:
                return json.load(cache_file)
        except Exception:
            return {}

    def _persist_cache_to_disk(self) -> None:
        try:
            with open(self._cache_file_path, "w") as cache_file:
                json.dump(self._in_memory_cache, cache_file, indent=2)
        except Exception:
            pass


def extract_unique_external_ips(network_flow_features: list[dict]) -> list[str]:
    private_prefixes = (
        "10.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "192.168.",
        "127.",
        "0.",
        "169.254.",
    )
    unique_ips: set[str] = set()
    for feature_dict in network_flow_features:
        ip_address = feature_dict.get("ip_address", "")
        if ip_address and not any(ip_address.startswith(prefix) for prefix in private_prefixes):
            unique_ips.add(ip_address)
    return sorted(unique_ips)


def _looks_like_ip_address(indicator: str) -> bool:
    parts = indicator.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
