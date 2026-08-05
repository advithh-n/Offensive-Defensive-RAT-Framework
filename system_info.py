"""
Module 1: System Information Gathering
MITRE ATT&CK: T1082 (System Information Discovery)
Collects OS, network, hardware, and running process info.
"""

import socket
import platform
import psutil
import os
import subprocess


def get_system_info():
    """Gather comprehensive system information."""
    info = {}

    # Basic system info
    info["hostname"] = socket.gethostname()
    info["os"] = f"{platform.system()} {platform.release()} {platform.version()}"
    info["architecture"] = platform.machine()
    info["processor"] = platform.processor()
    info["username"] = os.getlogin()
    info["home_directory"] = os.path.expanduser("~")

    # Network info
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info["local_ip"] = s.getsockname()[0]
        s.close()
    except Exception:
        info["local_ip"] = "unknown"

    info["mac_address"] = get_mac_address()

    # Hardware
    info["cpu_count"] = psutil.cpu_count()
    info["cpu_percent"] = psutil.cpu_percent(interval=1)
    info["ram_total_gb"] = round(psutil.virtual_memory().total / (1024**3), 2)
    info["ram_used_percent"] = psutil.virtual_memory().percent
    info["disk_total_gb"] = round(psutil.disk_usage("/").total / (1024**3), 2)
    info["disk_used_percent"] = psutil.disk_usage("/").used / psutil.disk_usage("/").total * 100

    # Running processes (top 20 by memory)
    processes = []
    for proc in psutil.process_iter(["pid", "name", "memory_percent"]):
        try:
            processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    processes.sort(key=lambda x: x.get("memory_percent", 0) or 0, reverse=True)
    info["top_processes"] = processes[:20]

    # Installed software (quick check via registry)
    info["installed_software"] = get_installed_software()

    # Wi-Fi profiles
    info["wifi_profiles"] = get_wifi_profiles()

    return info


def get_mac_address():
    """Get MAC address."""
    import uuid
    mac = uuid.getnode()
    return ':'.join(('%012x' % mac)[i:i+2] for i in range(0, 12, 2))


def get_installed_software():
    """Get list of installed software from registry."""
    software = []
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
             "Select-Object DisplayName, DisplayVersion | "
             "Where-Object { $_.DisplayName -ne $null } | "
             "Sort-Object DisplayName | "
             "Select-Object -First 30 | "
             "ConvertTo-Json"],
            capture_output=True, text=True, timeout=10
        )
        if result.stdout:
            import json
            software = json.loads(result.stdout)
    except Exception:
        software = ["Could not retrieve"]
    return software


def get_wifi_profiles():
    """Get saved Wi-Fi network names."""
    profiles = []
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "profiles"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split("\n"):
            if "All User Profile" in line:
                profile = line.split(":")[-1].strip()
                if profile:
                    profiles.append(profile)
    except Exception:
        pass
    return profiles


if __name__ == "__main__":
    import json
    info = get_system_info()
    print(json.dumps(info, indent=2, default=str))
