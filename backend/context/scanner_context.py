import socket
import time as time_module
from dataclasses import dataclass, field

from backend.models import ThreatCategory

# Categories that the tool itself generates when running Nmap —
# used to distinguish authorized recon from real attacker recon.
SCANNER_SUPPRESSED_CATEGORIES: frozenset[ThreatCategory] = frozenset({
    ThreatCategory.PORT_SCAN,
    ThreatCategory.RECON,
})


@dataclass
class ScannerContext:
    scanner_host_ip: str
    authorized_scanner_ips: set[str]
    scan_start_time: float
    scan_end_time: float
    suppressed_categories: frozenset[ThreatCategory] = field(
        default_factory=lambda: SCANNER_SUPPRESSED_CATEGORIES
    )


def detect_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def build_scanner_context(
    extra_authorized_ips: list[str] | None = None,
    scan_start_time: float | None = None,
    scan_end_time: float | None = None,
) -> ScannerContext:
    local_ip = detect_local_ip()
    authorized_ips: set[str] = {local_ip}
    if extra_authorized_ips:
        authorized_ips.update(extra_authorized_ips)
    now = time_module.time()
    return ScannerContext(
        scanner_host_ip=local_ip,
        authorized_scanner_ips=authorized_ips,
        scan_start_time=scan_start_time or now,
        scan_end_time=scan_end_time or now,
    )
