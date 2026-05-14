import ipaddress
import os
import platform
import signal
import socket
import subprocess
import time
from datetime import datetime

from backend.constants import CAPTURE_DEFAULT_DURATION_SECONDS, CAPTURE_OUTPUT_DIR

CAPTURE_SHUTDOWN_GRACE_SECONDS = 5


def detect_local_network() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe_socket:
        probe_socket.connect(("8.8.8.8", 80))
        local_ip = probe_socket.getsockname()[0]
    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return str(network)


def detect_default_interface() -> str:
    if platform.system() == "Darwin":
        result = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if "interface:" in line:
                return line.split()[-1]
        return "en0"

    result = subprocess.run(
        ["ip", "route", "show", "default"],
        capture_output=True, text=True, timeout=5,
    )
    parts = result.stdout.split()
    if "dev" in parts:
        return parts[parts.index("dev") + 1]
    return "eth0"


def capture_live_traffic(
    interface: str,
    duration: int = CAPTURE_DEFAULT_DURATION_SECONDS,
    output_dir: str = CAPTURE_OUTPUT_DIR,
) -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_path = os.path.join(output_dir, f"capture_{timestamp}.pcap")

    try:
        subprocess.run(
            ["tshark", "-i", interface, "-a", f"duration:{duration}", "-w", pcap_path],
            check=True,
            timeout=duration + 30,
        )
        return pcap_path
    except FileNotFoundError:
        pass

    # Fallback: tcpdump (terminate after duration seconds)
    proc = subprocess.Popen(
        ["tcpdump", "-i", interface, "-w", pcap_path],
        stderr=subprocess.DEVNULL,
    )
    time.sleep(duration)
    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=CAPTURE_SHUTDOWN_GRACE_SECONDS)
    return pcap_path
