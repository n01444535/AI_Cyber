import os
import subprocess
from datetime import datetime

from backend.constants import NMAP_DEFAULT_SCAN_ARGS, NMAP_OUTPUT_DIR

NMAP_SCAN_TIMEOUT_SECONDS = 900


def run_nmap_scan(
    target: str,
    scan_args: str = NMAP_DEFAULT_SCAN_ARGS,
    output_dir: str = NMAP_OUTPUT_DIR,
) -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    xml_path = os.path.join(output_dir, f"nmap_{timestamp}.xml")
    cmd = ["nmap"] + scan_args.split() + ["-oX", xml_path, target]
    subprocess.run(cmd, check=True, timeout=NMAP_SCAN_TIMEOUT_SECONDS)
    return xml_path
