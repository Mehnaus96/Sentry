"""
PacketSentry Environment & Dependency Verification Module
Validates system requirements, Tshark availability, and Python dependencies.
"""

import os
import shutil
import subprocess
import sys
from typing import Dict, Any, Optional

STANDARD_TSHARK_PATHS = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "/usr/bin/tshark",
    "/usr/local/bin/tshark",
]

def find_tshark_binary() -> Optional[str]:
    """
    Locates the tshark executable on the system.
    Checks PATH first, then standard installation paths.
    """
    # 1. Check system PATH
    path_tshark = shutil.which("tshark")
    if path_tshark:
        return path_tshark

    # 2. Check standard Windows/Unix locations
    for standard_path in STANDARD_TSHARK_PATHS:
        if os.path.exists(standard_path) and os.path.isfile(standard_path):
            return standard_path

    return None

def get_tshark_version(tshark_path: str) -> Optional[str]:
    """
    Executes tshark --version and extracts the version string safely.
    """
    try:
        res = subprocess.run(
            [tshark_path, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False
        )
        if res.returncode == 0 and res.stdout:
            # First line typically: TShark (Wireshark) x.y.z ...
            first_line = res.stdout.strip().splitlines()[0]
            return first_line
    except Exception as e:
        return f"Error executing tshark: {str(e)}"
    return None

def check_python_environment() -> Dict[str, Any]:
    """
    Checks Python version and required package imports.
    """
    required_packages = ["pandas", "plotly", "streamlit", "reportlab"]
    package_status = {}

    for pkg in required_packages:
        try:
            mod = __import__(pkg)
            version = getattr(mod, "__version__", "Installed")
            package_status[pkg] = {"installed": True, "version": str(version)}
        except ImportError:
            package_status[pkg] = {"installed": False, "version": None}

    return {
        "python_version": sys.version,
        "python_executable": sys.executable,
        "packages": package_status,
    }

def validate_environment() -> Dict[str, Any]:
    """
    Performs full environment diagnostic and returns status dictionary.
    """
    tshark_path = find_tshark_binary()
    tshark_ver = get_tshark_version(tshark_path) if tshark_path else None
    py_env = check_python_environment()

    all_packages_ok = all(info["installed"] for info in py_env["packages"].values())
    tshark_ok = tshark_path is not None and tshark_ver is not None

    return {
        "status": "READY" if (all_packages_ok and tshark_ok) else "INCOMPLETE",
        "tshark": {
            "available": tshark_ok,
            "path": tshark_path,
            "version": tshark_ver
        },
        "python": py_env
    }

if __name__ == "__main__":
    import json
    report = validate_environment()
    print(json.dumps(report, indent=2))
