"""
Custom Antivirus / RAT Detector
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

This is the DEFENSE side of the demo.
Detects the RAT by multiple methods, kills it, and cleans up.

Detection methods:
  1. Process-based detection (signature matching)
  2. Network-based detection (C2 connection detection)
  3. File signature scanning (YARA-style rule engine)
  4. Persistence mechanism detection (startup folder + registry)
  5. Memory scanning (process memory analysis)
  6. Behavioral analysis (registry diffs, keylogger patterns)
  7. Advanced network analysis (beaconing, data volume)
  8. Heuristic scoring (0-100 per process)

MITRE D3FEND mappings:
  D3-PM  - Process Monitoring
  D3-NTA - Network Traffic Analysis
  D3-FH  - File Hashing
  D3-FSB - File Content Signature-Based
  D3-MA  - Memory Analysis
  D3-BAN - Behavioral Analysis
"""

import psutil
import socket
import hashlib
import os
import sys
import time
import json
from datetime import datetime

# New imports
import av_signatures
import av_monitor

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


# ============ CONFIGURATION ============

# Known RAT signatures (we know our own RAT)
KNOWN_RAT_SIGNATURES = {
    "process_names": ["rat_client", "system_update_service"],
    "script_names": [
        "rat_client.py", "keylogger.py", "webcam_capture.py",
        "microphone_capture.py", "usb_monitor.py", "email_harvester.py",
    ],
    "c2_ports": [4444],
    "suspicious_imports": ["pynput", "ImageGrab"],
    "registry_keys": [],  # Would check persistence in real AV
}

# Colors for terminal output
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


def banner():
    print(f"""
{Colors.CYAN}{'='*55}
  CUSTOM ANTIVIRUS - RAT DETECTOR
  RMIT Cybersecurity Defense Demo
  Detection Engine v5.0 (8 scan methods + 26 YARA rules)
{'='*55}{Colors.END}
""")


# ============ DETECTION METHODS ============

def scan_processes():
    """
    Detection Method 1: Process-Based Scanning
    Checks running processes for known RAT signatures.
    """
    print(f"\n{Colors.BOLD}[SCAN 1] Process-Based Detection{Colors.END}")
    print("-" * 40)

    threats_found = []

    for proc in psutil.process_iter(["pid", "name", "cmdline", "connections"]):
        try:
            info = proc.info
            cmdline = " ".join(info["cmdline"]) if info["cmdline"] else ""

            # Check against known RAT process/script names
            for sig in KNOWN_RAT_SIGNATURES["script_names"]:
                if sig.lower() in cmdline.lower():
                    threat = {
                        "type": "process",
                        "pid": info["pid"],
                        "name": info["name"],
                        "cmdline": cmdline,
                        "signature": sig,
                        "severity": "CRITICAL",
                        "description": f"Known RAT script detected: {sig}"
                    }
                    threats_found.append(threat)
                    print(f"  {Colors.RED}[THREAT] PID {info['pid']}: {sig} detected in command line{Colors.END}")

            # Check for suspicious Python processes with keylogger imports
            if "python" in (info["name"] or "").lower():
                if "pynput" in cmdline or "keylogger" in cmdline:
                    threat = {
                        "type": "process",
                        "pid": info["pid"],
                        "name": info["name"],
                        "cmdline": cmdline,
                        "signature": "keylogger_behavior",
                        "severity": "HIGH",
                        "description": "Potential keylogger detected (pynput library in use)"
                    }
                    threats_found.append(threat)
                    print(f"  {Colors.RED}[THREAT] PID {info['pid']}: Keylogger behavior detected{Colors.END}")

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not threats_found:
        print(f"  {Colors.GREEN}[CLEAN] No malicious processes detected{Colors.END}")

    return threats_found


def scan_network():
    """
    Detection Method 2: Network-Based Detection
    Checks for connections to known C2 ports.
    """
    print(f"\n{Colors.BOLD}[SCAN 2] Network-Based Detection (C2 Connection){Colors.END}")
    print("-" * 40)

    threats_found = []

    for conn in psutil.net_connections(kind="inet"):
        try:
            if conn.status == "ESTABLISHED" and conn.raddr:
                remote_port = conn.raddr.port

                if remote_port in KNOWN_RAT_SIGNATURES["c2_ports"]:
                    # Find the process making this connection
                    proc_name = "unknown"
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                    except Exception:
                        pass

                    threat = {
                        "type": "network",
                        "pid": conn.pid,
                        "process": proc_name,
                        "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                        "severity": "CRITICAL",
                        "description": f"Active C2 connection on port {remote_port}"
                    }
                    threats_found.append(threat)
                    print(f"  {Colors.RED}[THREAT] C2 connection: {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}{Colors.END}")
                    print(f"           Process: {proc_name} (PID: {conn.pid})")

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not threats_found:
        print(f"  {Colors.GREEN}[CLEAN] No C2 connections detected{Colors.END}")

    return threats_found


def scan_files():
    """
    Detection Method 3: File Signature Scanning (YARA-style)
    Scans Python files using the YARA rule engine for known RAT patterns.
    """
    print(f"\n{Colors.BOLD}[SCAN 3] File Signature Scanning (YARA Rules){Colors.END}")
    print("-" * 40)

    threats_found = []

    # Scan common locations for RAT files
    scan_paths = [
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/Downloads"),
        os.path.expanduser("~/AppData/Local/Temp"),
    ]

    # Also check the AppData persistence directory
    persist_dir = os.path.join(
        os.environ.get("APPDATA", ""),
        "Microsoft", "WindowsSecurityHealth"
    )
    if os.path.exists(persist_dir):
        scan_paths.append(persist_dir)

    for scan_path in scan_paths:
        if not os.path.exists(scan_path):
            continue

        for root, dirs, files in os.walk(scan_path):
            for fname in files:
                if not fname.endswith(".py"):
                    continue

                full_path = os.path.join(root, fname)

                # Run YARA-style rule scan
                matches = av_signatures.scan_file(full_path)
                for match in matches:
                    threat = {
                        "type": "file_signature",
                        "path": full_path,
                        "filename": fname,
                        "rule": match["rule"],
                        "mitre": match["mitre"],
                        "severity": match["severity"],
                        "matched_strings": len(match["matched_strings"]),
                        "description": f"YARA rule hit: {match['rule']} ({match['description']})"
                    }
                    threats_found.append(threat)
                    print(f"  {Colors.RED}[THREAT] {fname}: {match['rule']} ({match['severity']}) - {match['mitre']}{Colors.END}")
                    print(f"           Matched {match['matched_count']}/{match['total_strings']} strings")

                # Also check for known filenames
                if fname in KNOWN_RAT_SIGNATURES["script_names"]:
                    file_hash = hash_file(full_path)
                    threat = {
                        "type": "file",
                        "path": full_path,
                        "filename": fname,
                        "hash_sha256": file_hash,
                        "severity": "CRITICAL",
                        "description": f"Known RAT file found: {fname}"
                    }
                    threats_found.append(threat)
                    print(f"  {Colors.RED}[THREAT] RAT file found: {full_path}{Colors.END}")
                    print(f"           SHA256: {file_hash[:32]}...")

    if not threats_found:
        print(f"  {Colors.GREEN}[CLEAN] No malicious files detected{Colors.END}")

    return threats_found


def scan_persistence():
    """
    Detection Method 4: Persistence Mechanism Detection
    Checks startup folders AND registry Run keys for RAT persistence.
    """
    print(f"\n{Colors.BOLD}[SCAN 4] Persistence Mechanism Detection{Colors.END}")
    print("-" * 40)

    threats_found = []

    # Check startup folder (existing)
    startup_folder = os.path.join(
        os.environ.get("APPDATA", ""),
        "Microsoft", "Windows", "Start Menu", "Programs", "Startup"
    )
    if os.path.exists(startup_folder):
        for fname in os.listdir(startup_folder):
            if any(sig in fname.lower() for sig in ["rat", "keylog", "system_update"]):
                threat = {
                    "type": "persistence",
                    "location": "startup_folder",
                    "path": os.path.join(startup_folder, fname),
                    "severity": "CRITICAL",
                    "description": f"Suspicious startup entry: {fname}"
                }
                threats_found.append(threat)
                print(f"  {Colors.RED}[THREAT] Suspicious startup entry: {fname}{Colors.END}")

    # NEW: Check registry HKCU Run keys
    if HAS_WINREG:
        suspicious_names = ["windowssecurityhealth", "system_update", "rat", "edu_rat"]
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_READ
            )
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    # Check if the value points to a suspicious path or name
                    name_lower = name.lower()
                    value_lower = value.lower()

                    is_suspicious = (
                        any(s in name_lower for s in suspicious_names) or
                        "rat_client" in value_lower or
                        "keylogger" in value_lower or
                        "windowssecurityhealth" in value_lower
                    )

                    if is_suspicious:
                        threat = {
                            "type": "persistence",
                            "location": "registry_run_key",
                            "name": name,
                            "value": value,
                            "severity": "CRITICAL",
                            "description": f"Suspicious registry Run key: {name} -> {value}"
                        }
                        threats_found.append(threat)
                        print(f"  {Colors.RED}[THREAT] Registry Run key: {name}{Colors.END}")
                        print(f"           Value: {value[:100]}")

                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass

    # NEW: Check for scheduled task persistence (T1053.005)
    try:
        import subprocess
        result = subprocess.run(
            'schtasks /Query /TN "WindowsSecurityHealthCheck" /FO LIST',
            shell=True, capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            threat = {
                "type": "persistence",
                "location": "scheduled_task",
                "name": "WindowsSecurityHealthCheck",
                "severity": "CRITICAL",
                "description": "Suspicious scheduled task: WindowsSecurityHealthCheck"
            }
            threats_found.append(threat)
            print(f"  {Colors.RED}[THREAT] Scheduled task: WindowsSecurityHealthCheck{Colors.END}")
    except Exception:
        pass

    # NEW: Check startup folder for .bat persistence
    startup_bat = os.path.join(startup_folder, "WindowsSecurityHealth.bat")
    if os.path.exists(startup_bat):
        threat = {
            "type": "persistence",
            "location": "startup_folder_bat",
            "path": startup_bat,
            "severity": "CRITICAL",
            "description": f"RAT startup .bat file: {startup_bat}"
        }
        threats_found.append(threat)
        print(f"  {Colors.RED}[THREAT] Startup .bat: {startup_bat}{Colors.END}")

    # Check persistence directory
    persist_dir = os.path.join(
        os.environ.get("APPDATA", ""),
        "Microsoft", "WindowsSecurityHealth"
    )
    if os.path.exists(persist_dir):
        threat = {
            "type": "persistence",
            "location": "appdata_directory",
            "path": persist_dir,
            "severity": "CRITICAL",
            "description": f"RAT persistence directory found: {persist_dir}"
        }
        threats_found.append(threat)
        print(f"  {Colors.RED}[THREAT] Persistence directory: {persist_dir}{Colors.END}")
        try:
            files = os.listdir(persist_dir)
            print(f"           Contains: {', '.join(files[:5])}{'...' if len(files) > 5 else ''}")
        except Exception:
            pass

    if not threats_found:
        print(f"  {Colors.GREEN}[CLEAN] No persistence mechanisms detected{Colors.END}")

    return threats_found


def scan_memory():
    """
    Detection Method 5: Memory Scanning
    Scans Python process memory for C2 URLs, known strings, encryption keys.
    """
    print(f"\n{Colors.BOLD}[SCAN 5] Memory Scanning{Colors.END}")
    print("-" * 40)

    threats_found = []

    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = (proc.info["name"] or "").lower()
            if "python" not in name:
                continue

            pid = proc.info["pid"]
            findings = av_monitor.scan_process_memory(pid)
            for f in findings:
                threat = {
                    "type": "memory",
                    "pid": pid,
                    "severity": f["severity"],
                    "description": f["detail"]
                }
                threats_found.append(threat)
                print(f"  {Colors.RED}[THREAT] {f['detail']}{Colors.END}")

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not threats_found:
        print(f"  {Colors.GREEN}[CLEAN] No suspicious memory content detected{Colors.END}")

    return threats_found


def scan_behavior():
    """
    Detection Method 6: Behavioral Analysis
    Checks registry changes, keylogger patterns, mass file reads, child processes.
    """
    print(f"\n{Colors.BOLD}[SCAN 6] Behavioral Analysis{Colors.END}")
    print("-" * 40)

    threats_found = []
    monitor = av_monitor.BehavioralMonitor()
    findings = monitor.full_check()

    for f in findings:
        threat = {
            "type": "behavioral",
            "severity": f["severity"],
            "description": f["detail"],
            "mitre": f.get("mitre", "")
        }
        threats_found.append(threat)
        print(f"  {Colors.RED}[THREAT] [{f['severity']}] {f['detail']}{Colors.END}")

    if not threats_found:
        print(f"  {Colors.GREEN}[CLEAN] No suspicious behavior detected{Colors.END}")

    return threats_found


def scan_network_advanced():
    """
    Detection Method 7: Advanced Network Analysis
    Beacon detection, unusual ports, data volume, connection persistence.
    """
    print(f"\n{Colors.BOLD}[SCAN 7] Advanced Network Analysis{Colors.END}")
    print("-" * 40)

    threats_found = []
    analyzer = av_monitor.NetworkAnalyzer()
    findings = analyzer.analyze()

    for f in findings:
        threat = {
            "type": "network_advanced",
            "severity": f["severity"],
            "description": f["detail"],
            "mitre": f.get("mitre", "")
        }
        threats_found.append(threat)
        print(f"  {Colors.RED}[THREAT] [{f['severity']}] {f['detail']}{Colors.END}")

    if not threats_found:
        print(f"  {Colors.GREEN}[CLEAN] No suspicious network patterns detected{Colors.END}")

    return threats_found


def scan_heuristics():
    """
    Detection Method 8: Heuristic Scoring
    Assigns suspicion score (0-100) to each running process.
    """
    print(f"\n{Colors.BOLD}[SCAN 8] Heuristic Scoring{Colors.END}")
    print("-" * 40)

    threats_found = []
    scorer = av_monitor.HeuristicScorer()
    scores = scorer.score_all_processes()

    for s in scores:
        if s["score"] >= 75:
            level = f"{Colors.RED}CONFIRMED MALWARE{Colors.END}"
        elif s["score"] >= 50:
            level = f"{Colors.YELLOW}LIKELY MALICIOUS{Colors.END}"
        elif s["score"] >= 25:
            level = f"{Colors.YELLOW}SUSPICIOUS{Colors.END}"
        else:
            continue

        print(f"  PID {s['pid']} ({s['name']}): score={s['score']}/100 - {level}")
        for reason in s["reasons"]:
            print(f"    {reason}")

        if s["score"] >= 50:
            threat = {
                "type": "heuristic",
                "pid": s["pid"],
                "name": s["name"],
                "score": s["score"],
                "reasons": s["reasons"],
                "severity": "CRITICAL" if s["score"] >= 75 else "HIGH",
                "description": f"Heuristic score {s['score']}/100 for {s['name']} (PID {s['pid']})"
            }
            threats_found.append(threat)

    if not threats_found:
        print(f"  {Colors.GREEN}[CLEAN] All processes scored below threat threshold{Colors.END}")

    return threats_found


# ============ HELPER FUNCTIONS ============

def hash_file(filepath):
    """Calculate SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return "hash_error"


# ============ RESPONSE ACTIONS ============

def kill_threat(threat):
    """Terminate a malicious process."""
    pid = threat.get("pid")
    if pid:
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=5)
            print(f"  {Colors.GREEN}[KILLED] Process {pid} terminated{Colors.END}")
            return True
        except psutil.NoSuchProcess:
            print(f"  {Colors.YELLOW}[INFO] Process {pid} already gone{Colors.END}")
            return True
        except psutil.AccessDenied:
            print(f"  {Colors.RED}[FAILED] Access denied killing PID {pid} - run as admin{Colors.END}")
            return False
        except Exception as e:
            print(f"  {Colors.RED}[FAILED] Could not kill PID {pid}: {e}{Colors.END}")
            return False
    return False


def quarantine_file(filepath):
    """Move a malicious file to quarantine."""
    quarantine_dir = os.path.join(os.path.dirname(filepath), ".quarantine")
    os.makedirs(quarantine_dir, exist_ok=True)

    quarantine_path = os.path.join(quarantine_dir, os.path.basename(filepath) + ".quarantined")
    try:
        os.rename(filepath, quarantine_path)
        print(f"  {Colors.GREEN}[QUARANTINED] {filepath} -> {quarantine_path}{Colors.END}")
        return True
    except Exception as e:
        print(f"  {Colors.RED}[FAILED] Could not quarantine: {e}{Colors.END}")
        return False


# ============ MAIN SCAN ENGINE ============

def full_scan():
    """Run all 8 detection methods and generate report."""
    banner()
    scan_start = datetime.now()

    print(f"[*] Scan started at {scan_start.isoformat()}")
    print(f"[*] Running 8 detection methods...\n")

    all_threats = []

    # Run all scans (original 4 + new 4)
    all_threats.extend(scan_processes())       # 1. Process-based
    all_threats.extend(scan_network())         # 2. Network (C2 port)
    all_threats.extend(scan_files())           # 3. YARA signatures
    all_threats.extend(scan_persistence())     # 4. Persistence
    all_threats.extend(scan_memory())          # 5. Memory
    all_threats.extend(scan_behavior())        # 6. Behavioral
    all_threats.extend(scan_network_advanced()) # 7. Advanced network
    all_threats.extend(scan_heuristics())      # 8. Heuristics

    # Summary
    scan_end = datetime.now()
    duration = (scan_end - scan_start).total_seconds()

    print(f"\n{'='*55}")
    print(f"{Colors.BOLD}  SCAN COMPLETE - RESULTS{Colors.END}")
    print(f"{'='*55}")
    print(f"  Duration: {duration:.2f} seconds")
    print(f"  Threats found: {len(all_threats)}")

    critical = sum(1 for t in all_threats if t["severity"] == "CRITICAL")
    high = sum(1 for t in all_threats if t["severity"] == "HIGH")
    medium = sum(1 for t in all_threats if t.get("severity") == "MEDIUM")
    print(f"  Critical: {Colors.RED}{critical}{Colors.END}")
    print(f"  High: {Colors.YELLOW}{high}{Colors.END}")
    print(f"  Medium: {Colors.CYAN}{medium}{Colors.END}")

    if all_threats:
        print(f"\n{Colors.RED}[!] THREATS DETECTED - Recommend immediate action{Colors.END}")
        response = input(f"\n{Colors.BOLD}Kill malicious processes and quarantine files? (y/n): {Colors.END}")

        if response.lower() == "y":
            print(f"\n{Colors.BOLD}[*] Executing response actions...{Colors.END}")
            for threat in all_threats:
                if threat["type"] in ["process", "network", "memory", "behavioral",
                                       "network_advanced", "heuristic"]:
                    kill_threat(threat)
                elif threat["type"] in ["file", "file_signature", "file_content"]:
                    quarantine_file(threat.get("path", ""))
            print(f"\n{Colors.GREEN}[+] Response actions complete. System cleaned.{Colors.END}")
        else:
            print(f"\n{Colors.YELLOW}[*] No action taken. Threats still active.{Colors.END}")
    else:
        print(f"\n{Colors.GREEN}[+] System is clean. No threats detected.{Colors.END}")

    # Save scan report
    report = {
        "scan_time": scan_start.isoformat(),
        "duration_seconds": duration,
        "threats_found": len(all_threats),
        "scan_methods": 8,
        "threats": all_threats,
        "actions_taken": response.lower() == "y" if all_threats else False
    }

    report_path = os.path.join(os.path.dirname(__file__), "scan_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[*] Scan report saved to: {report_path}")

    return all_threats


def continuous_mode():
    """Run continuous monitoring with all detection engines."""
    banner()
    print(f"[*] Starting continuous monitoring mode...")
    monitor = av_monitor.ContinuousMonitor(scan_interval=30)
    monitor.run()


# ============ ENTRY POINT ============

if __name__ == "__main__":
    if "--monitor" in sys.argv:
        continuous_mode()
    else:
        full_scan()
