"""
Advanced Antivirus Monitor - Behavioral, Memory, Network, Heuristic Detection
MITRE D3FEND: D3-MA  (Memory Analysis)
               D3-BAN (Behavioral Analysis)
               D3-NTA (Network Traffic Analysis)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Five detection engines:
  1. BehavioralMonitor  — registry diffs, keylogger patterns, mass file reads
  2. Memory scanner     — scan process memory for C2 URLs, known strings, keys
  3. NetworkAnalyzer    — beacon detection, unusual ports, data volume
  4. HeuristicScorer    — 0-100 suspicion score per process
  5. ContinuousMonitor  — main loop orchestrating all engines
"""

import os
import re
import time
import json
import math
import ctypes
import struct
import psutil
from datetime import datetime
from collections import defaultdict

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


# Terminal colors (reuse from antivirus.py)
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


# ============ ENGINE 1: BEHAVIORAL MONITOR (D3-BAN) ============

class BehavioralMonitor:
    """
    Monitors system behavior for RAT-like activity:
    - Registry Run key changes (new entries = persistence)
    - Keylogger patterns (pynput + low CPU + persistent)
    - Mass file reads (>1000 reads in 60s)
    - Suspicious child processes (Python spawning cmd/powershell)
    """

    def __init__(self):
        self._registry_snapshot = {}
        self._io_baseline = {}  # pid -> (read_count, timestamp)
        self._take_registry_snapshot()

    def _take_registry_snapshot(self):
        """Snapshot all HKCU Run key values."""
        if not HAS_WINREG:
            return
        self._registry_snapshot = {}
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
                    self._registry_snapshot[name] = value
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass

    def check_registry_changes(self):
        """Compare current Run keys against baseline, return new entries."""
        if not HAS_WINREG:
            return []

        threats = []
        current = {}
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
                    current[name] = value
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            return threats

        # Find new entries
        for name, value in current.items():
            if name not in self._registry_snapshot:
                threats.append({
                    "type": "registry_persistence",
                    "detail": f"New Run key: {name} = {value}",
                    "severity": "CRITICAL",
                    "mitre": "T1547.001",
                })

        # Update snapshot
        self._registry_snapshot = current
        return threats

    def check_keylogger_patterns(self):
        """Detect processes with keylogger characteristics."""
        threats = []
        for proc in psutil.process_iter(["pid", "name", "cmdline", "cpu_percent"]):
            try:
                info = proc.info
                cmdline = " ".join(info["cmdline"]) if info["cmdline"] else ""
                name = (info["name"] or "").lower()

                if "python" not in name:
                    continue

                # Keylogger indicators: pynput or keyboard in cmdline, low CPU
                has_pynput = "pynput" in cmdline.lower() or "keylogger" in cmdline.lower()
                has_keyboard = "keyboard" in cmdline.lower()

                if has_pynput or has_keyboard:
                    threats.append({
                        "type": "keylogger_detected",
                        "pid": info["pid"],
                        "detail": f"PID {info['pid']}: pynput/keyboard in cmdline",
                        "severity": "CRITICAL",
                        "mitre": "T1056.001",
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return threats

    def check_mass_file_reads(self):
        """Detect processes with abnormally high file read counts."""
        threats = []
        now = time.time()

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                io = proc.io_counters()
                pid = proc.info["pid"]

                if pid in self._io_baseline:
                    prev_count, prev_time = self._io_baseline[pid]
                    elapsed = now - prev_time
                    if elapsed > 0:
                        reads_per_min = (io.read_count - prev_count) / elapsed * 60
                        if reads_per_min > 1000:
                            threats.append({
                                "type": "mass_file_read",
                                "pid": pid,
                                "detail": f"PID {pid}: {reads_per_min:.0f} reads/min",
                                "severity": "HIGH",
                                "mitre": "T1005",
                            })

                self._io_baseline[pid] = (io.read_count, now)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return threats

    def check_suspicious_children(self):
        """Detect Python processes spawning cmd.exe or powershell.exe."""
        threats = []
        for proc in psutil.process_iter(["pid", "name", "ppid"]):
            try:
                name = (proc.info["name"] or "").lower()
                if name in ["cmd.exe", "powershell.exe"]:
                    try:
                        parent = psutil.Process(proc.info["ppid"])
                        parent_name = (parent.name() or "").lower()
                        if "python" in parent_name:
                            threats.append({
                                "type": "suspicious_child_process",
                                "pid": proc.info["pid"],
                                "detail": f"Python (PID {proc.info['ppid']}) spawned {name} (PID {proc.info['pid']})",
                                "severity": "HIGH",
                                "mitre": "T1059.003",
                            })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return threats

    def full_check(self):
        """Run all behavioral checks."""
        threats = []
        threats.extend(self.check_registry_changes())
        threats.extend(self.check_keylogger_patterns())
        threats.extend(self.check_mass_file_reads())
        threats.extend(self.check_suspicious_children())
        return threats


# ============ ENGINE 2: MEMORY SCANNER (D3-MA) ============

# Windows API constants
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

# Known malicious strings to search for in memory
MEMORY_SIGNATURES = [
    b"send_to_c2",
    b"C2_HOST",
    b"kill_switch",
    b"exfiltrate",
    b"encrypt_payload",
    b"keylog",
    b"ImageGrab",
    b"pynput",
    b"AES",
    # New signatures for Phase 9-11 features
    b"wifi_stealer",
    b"harvest_discord_tokens",
    b"harvest_ssh_keys",
    b"harvest_cloud_credentials",
    b"full_network_recon",
    b"anti_forensics",
    b"BEACON_JITTER",
    # New signatures for Phase 12-13 features
    b"lateral_recon",
    b"scan_host_ports",
    b"enumerate_remote_shares",
    b"check_admin_shares",
    b"clear_event_log",
    b"wevtutil",
    # New signatures for Phase 14-20 features
    b"webcam_capture",
    b"capture_webcam_image",
    b"VideoCapture",
    b"microphone_capture",
    b"record_audio",
    b"sounddevice",
    b"scheduled_task_persist",
    b"schtasks",
    b"usb_monitor",
    b"removable_drives",
    b"geolocation",
    b"ip-api.com",
    b"injection_recon",
    b"VirtualAllocEx",
    b"email_harvester",
    b"harvest_outlook",
]

# C2 URL regex pattern
C2_URL_PATTERN = re.compile(rb"http://\d+\.\d+\.\d+\.\d+:\d+")


def scan_process_memory(pid):
    """
    Scan a process's memory for known malicious strings.
    Uses ReadProcessMemory via ctypes Windows API.
    Falls back to cmdline + open_files if access denied.

    Returns:
        list of findings (dicts with type, detail, severity)
    """
    findings = []

    # Try direct memory read first
    try:
        kernel32 = ctypes.windll.kernel32

        handle = kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            False, pid
        )

        if handle:
            # Read up to 1MB from common memory regions
            buf_size = 4096
            buffer = ctypes.create_string_buffer(buf_size)
            bytes_read = ctypes.c_size_t()

            # Sample memory at various offsets
            collected = b""
            for base_addr in range(0x00400000, 0x00800000, buf_size):
                try:
                    success = kernel32.ReadProcessMemory(
                        handle,
                        ctypes.c_void_p(base_addr),
                        buffer,
                        buf_size,
                        ctypes.byref(bytes_read)
                    )
                    if success and bytes_read.value > 0:
                        collected += buffer.raw[:bytes_read.value]
                except Exception:
                    continue

                # Stop after collecting enough
                if len(collected) > 1024 * 1024:
                    break

            kernel32.CloseHandle(handle)

            # Scan collected memory
            for sig in MEMORY_SIGNATURES:
                if sig in collected:
                    findings.append({
                        "type": "memory_string",
                        "detail": f"Found '{sig.decode(errors='replace')}' in PID {pid} memory",
                        "severity": "HIGH",
                    })

            # Check for C2 URLs
            urls = C2_URL_PATTERN.findall(collected)
            for url in urls:
                findings.append({
                    "type": "memory_c2_url",
                    "detail": f"C2 URL in memory: {url.decode(errors='replace')}",
                    "severity": "CRITICAL",
                })

            # Check for high-entropy sequences (potential encryption keys)
            for i in range(0, len(collected) - 32, 32):
                chunk = collected[i:i+32]
                entropy = _calc_entropy(chunk)
                if entropy > 7.5:  # Near-random = likely key material
                    findings.append({
                        "type": "memory_high_entropy",
                        "detail": f"High-entropy 32-byte sequence at offset {i} (entropy={entropy:.2f})",
                        "severity": "MEDIUM",
                    })
                    break  # Only report first one

            return findings

    except Exception:
        pass

    # Fallback: check cmdline and open files
    try:
        proc = psutil.Process(pid)
        cmdline = " ".join(proc.cmdline()).lower()

        for sig in [s.decode() for s in MEMORY_SIGNATURES]:
            if sig.lower() in cmdline:
                findings.append({
                    "type": "cmdline_string",
                    "detail": f"Found '{sig}' in PID {pid} cmdline",
                    "severity": "MEDIUM",
                })

        # Check open files
        try:
            for f in proc.open_files():
                fname = os.path.basename(f.path).lower()
                if any(s in fname for s in ["rat", "keylog", "c2", "exfil"]):
                    findings.append({
                        "type": "suspicious_open_file",
                        "detail": f"PID {pid} has open file: {f.path}",
                        "severity": "HIGH",
                    })
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

    return findings


def _calc_entropy(data):
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0
    freq = defaultdict(int)
    for byte in data:
        freq[byte] += 1
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in freq.values() if c > 0)


# ============ ENGINE 3: NETWORK ANALYZER (D3-NTA) ============

class NetworkAnalyzer:
    """
    Monitors network connections for RAT-like patterns:
    - Beacon detection (regular interval connections)
    - Unusual ports (non-standard: not 80/443/53/22/8080/8443)
    - Data volume (>10MB sent in 5 min)
    - Connection persistence (>30 min to non-standard port)
    """

    STANDARD_PORTS = {80, 443, 53, 22, 8080, 8443}

    def __init__(self):
        self._connection_timestamps = defaultdict(list)  # pid -> [timestamps]
        self._connection_start = {}  # (pid, remote) -> first_seen
        self._bytes_sent_baseline = {}  # pid -> (bytes, timestamp)

    def analyze(self):
        """Run all network analysis checks."""
        threats = []
        now = time.time()

        for conn in psutil.net_connections(kind="inet"):
            try:
                if conn.status != "ESTABLISHED" or not conn.raddr:
                    continue

                pid = conn.pid
                remote_port = conn.raddr.port
                remote_key = (pid, f"{conn.raddr.ip}:{conn.raddr.port}")

                # Track connection timestamps for beacon detection
                self._connection_timestamps[pid].append(now)
                # Keep only last 20 timestamps
                self._connection_timestamps[pid] = self._connection_timestamps[pid][-20:]

                # Track connection start times
                if remote_key not in self._connection_start:
                    self._connection_start[remote_key] = now

                # 1. Unusual port detection
                if remote_port not in self.STANDARD_PORTS:
                    proc_name = "unknown"
                    try:
                        proc_name = psutil.Process(pid).name()
                    except Exception:
                        pass

                    # Port 4444 is especially suspicious (common RAT/Metasploit)
                    severity = "CRITICAL" if remote_port == 4444 else "HIGH"
                    threats.append({
                        "type": "unusual_port",
                        "pid": pid,
                        "detail": f"PID {pid} ({proc_name}): connection to port {remote_port}",
                        "severity": severity,
                        "mitre": "T1041",
                    })

                # 2. Connection persistence check (>30 min on non-standard port)
                if remote_port not in self.STANDARD_PORTS:
                    duration = now - self._connection_start.get(remote_key, now)
                    if duration > 1800:  # 30 minutes
                        threats.append({
                            "type": "persistent_connection",
                            "pid": pid,
                            "detail": f"PID {pid}: {duration/60:.0f} min connection to port {remote_port}",
                            "severity": "HIGH",
                            "mitre": "T1071",
                        })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # 3. Beacon detection (check regularity of connection intervals)
        for pid, timestamps in self._connection_timestamps.items():
            if len(timestamps) >= 5:
                intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                if intervals:
                    avg = sum(intervals) / len(intervals)
                    if avg > 0:
                        std_dev = (sum((x - avg)**2 for x in intervals) / len(intervals)) ** 0.5
                        if std_dev < 5 and avg < 120:  # Regular beaconing < 2 min intervals
                            threats.append({
                                "type": "beacon_detected",
                                "pid": pid,
                                "detail": f"PID {pid}: regular beaconing (avg={avg:.1f}s, std={std_dev:.1f}s)",
                                "severity": "CRITICAL",
                                "mitre": "T1071",
                            })

        # 4. Data volume check
        for proc in psutil.process_iter(["pid"]):
            try:
                io = proc.io_counters()
                pid = proc.info["pid"]

                if pid in self._bytes_sent_baseline:
                    prev_bytes, prev_time = self._bytes_sent_baseline[pid]
                    elapsed = now - prev_time
                    if elapsed > 0:
                        bytes_sent = io.write_bytes - prev_bytes
                        mb_per_5min = (bytes_sent / (1024*1024)) * (300 / elapsed)
                        if mb_per_5min > 10:
                            threats.append({
                                "type": "high_data_volume",
                                "pid": pid,
                                "detail": f"PID {pid}: {mb_per_5min:.1f} MB/5min sent",
                                "severity": "HIGH",
                                "mitre": "T1041",
                            })

                self._bytes_sent_baseline[pid] = (io.write_bytes, now)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return threats


# ============ ENGINE 4: HEURISTIC SCORER ============

class HeuristicScorer:
    """
    Assigns a 0-100 suspicion score to each process based on
    a weighted combination of behavioral indicators.

    Score thresholds:
      0-24:  Clean
      25-49: Suspicious (log)
      50-74: Likely malicious (watchlist)
      75-100: Confirmed malware (auto-quarantine)
    """

    # Import combination scoring rules
    IMPORT_RULES = [
        (["pynput", "requests"], 30),
        (["winreg", "requests"], 25),
        (["ImageGrab", "base64", "requests"], 25),
        (["win32clipboard", "requests"], 20),
        (["win32crypt", "sqlite3"], 35),
        (["Crypto.Cipher", "requests"], 20),
        (["subprocess", "requests"], 30),
        # New rules for Phase 9-11 features
        (["netsh", "wlan", "key=clear"], 30),         # Wi-Fi password extraction
        (["leveldb", "discord"], 35),                  # Discord token theft
        (["ssh", "PRIVATE KEY"], 30),                  # SSH key theft
        (["aws", "credentials", "azure"], 25),         # Cloud cred theft
        (["arp", "net_connections", "displaydns"], 25), # Network recon
        # New rules for Phase 12-13 features
        (["net view", "ADMIN$", "scan_port"], 35),     # Lateral movement recon
        (["connect_ex", "ThreadPoolExecutor"], 25),     # Port scanner
        (["wevtutil", "clear_event_log"], 40),          # Event log tampering
        # New rules for Phase 14-20 features
        (["cv2", "VideoCapture", "imencode"], 35),         # Webcam capture
        (["sounddevice", "record", "wave"], 35),           # Microphone capture
        (["schtasks", "ONLOGON"], 30),                     # Scheduled task persistence
        (["GetDriveTypeW", "removable"], 25),              # USB monitoring
        (["ip-api.com", "geolocation"], 20),               # Geolocation
        (["VirtualAllocEx", "WriteProcessMemory"], 40),    # Process injection recon
        (["Outlook", "Thunderbird", "logins.json"], 30),   # Email harvesting
    ]

    def score_process(self, proc):
        """
        Calculate suspicion score for a single process.

        Returns:
            dict with pid, name, score, reasons
        """
        score = 0
        reasons = []

        try:
            pid = proc.pid
            name = proc.name()
            cmdline = " ".join(proc.cmdline()) if proc.cmdline() else ""
            cmdline_lower = cmdline.lower()

            # Skip non-Python processes
            if "python" not in name.lower():
                return {"pid": pid, "name": name, "score": 0, "reasons": []}

            # Import combination checks
            for imports, points in self.IMPORT_RULES:
                if all(imp.lower() in cmdline_lower for imp in imports):
                    score += points
                    reasons.append(f"Imports: {'+'.join(imports)} (+{points})")

            # Process age > 1 hour
            try:
                create_time = proc.create_time()
                age_hours = (time.time() - create_time) / 3600
                if age_hours > 1:
                    score += 10
                    reasons.append(f"Long-running: {age_hours:.1f}h (+10)")
            except Exception:
                pass

            # No visible window (hidden process)
            try:
                if os.name == "nt" and "pythonw" in cmdline_lower:
                    score += 15
                    reasons.append("No visible window (pythonw) (+15)")
            except Exception:
                pass

            # Non-standard port connections
            try:
                conns = proc.net_connections()
                for conn in conns:
                    if conn.status == "ESTABLISHED" and conn.raddr:
                        if conn.raddr.port not in NetworkAnalyzer.STANDARD_PORTS:
                            score += 15
                            reasons.append(f"Non-standard port: {conn.raddr.port} (+15)")
                            break
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # High I/O read count
            try:
                io = proc.io_counters()
                if io.read_count > 100000:
                    score += 10
                    reasons.append(f"High I/O reads: {io.read_count} (+10)")
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # Cap at 100
            score = min(score, 100)

            return {"pid": pid, "name": name, "score": score, "reasons": reasons}

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def score_all_processes(self):
        """Score all running processes, return sorted by score descending."""
        results = []
        for proc in psutil.process_iter():
            result = self.score_process(proc)
            if result and result["score"] > 0:
                results.append(result)

        results.sort(key=lambda x: x["score"], reverse=True)
        return results


# ============ ENGINE 5: CONTINUOUS MONITOR ============

class ContinuousMonitor:
    """
    Main monitoring loop that orchestrates all detection engines.

    Cycle: process scan -> network scan -> behavioral check ->
           memory scan on suspects -> heuristic scoring

    Auto-quarantine at score >= 75
    Watchlist at 50-74 (escalate if persists 3 cycles)
    Log at 25-49
    """

    def __init__(self, scan_interval=30):
        self.scan_interval = scan_interval
        self.behavioral = BehavioralMonitor()
        self.network = NetworkAnalyzer()
        self.heuristic = HeuristicScorer()
        self.watchlist = {}  # pid -> cycle_count
        self.cycle = 0

    def run(self):
        """Main monitoring loop (blocking)."""
        print(f"\n{Colors.CYAN}{'='*55}")
        print(f"  CONTINUOUS MONITORING MODE")
        print(f"  Scan interval: {self.scan_interval} seconds")
        print(f"  Press Ctrl+C to stop")
        print(f"{'='*55}{Colors.END}\n")

        try:
            while True:
                self.cycle += 1
                self._run_cycle()
                time.sleep(self.scan_interval)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Monitoring stopped by user{Colors.END}")

    def _run_cycle(self):
        """Execute one full monitoring cycle."""
        cycle_start = datetime.now()
        all_threats = []

        print(f"\n{Colors.BOLD}--- Cycle #{self.cycle} ({cycle_start.strftime('%H:%M:%S')}) ---{Colors.END}")

        # 1. Behavioral analysis
        behavioral_threats = self.behavioral.full_check()
        all_threats.extend(behavioral_threats)
        if behavioral_threats:
            for t in behavioral_threats:
                print(f"  {Colors.RED}[BEHAVIORAL] [{t['severity']}] {t['detail']}{Colors.END}")

        # 2. Network analysis
        network_threats = self.network.analyze()
        all_threats.extend(network_threats)
        if network_threats:
            for t in network_threats:
                print(f"  {Colors.RED}[NETWORK] [{t['severity']}] {t['detail']}{Colors.END}")

        # 3. Heuristic scoring
        scores = self.heuristic.score_all_processes()
        for s in scores:
            if s["score"] >= 75:
                print(f"  {Colors.RED}[HEURISTIC] PID {s['pid']} ({s['name']}): "
                      f"score={s['score']}/100 CONFIRMED MALWARE{Colors.END}")
                for reason in s["reasons"]:
                    print(f"    {reason}")

                # Auto-quarantine
                self._handle_threat(s["pid"], s["score"])

            elif s["score"] >= 50:
                print(f"  {Colors.YELLOW}[HEURISTIC] PID {s['pid']} ({s['name']}): "
                      f"score={s['score']}/100 WATCHLIST{Colors.END}")
                # Track on watchlist
                self.watchlist[s["pid"]] = self.watchlist.get(s["pid"], 0) + 1
                if self.watchlist[s["pid"]] >= 3:
                    print(f"  {Colors.RED}[ESCALATED] PID {s['pid']} on watchlist for 3+ cycles{Colors.END}")
                    self._handle_threat(s["pid"], s["score"])

            elif s["score"] >= 25:
                print(f"  {Colors.YELLOW}[HEURISTIC] PID {s['pid']} ({s['name']}): "
                      f"score={s['score']}/100 suspicious{Colors.END}")

        # 4. Memory scan on high-scoring processes
        suspect_pids = [s["pid"] for s in scores if s["score"] >= 50]
        for pid in suspect_pids:
            mem_findings = scan_process_memory(pid)
            if mem_findings:
                for f in mem_findings:
                    print(f"  {Colors.RED}[MEMORY] [{f['severity']}] {f['detail']}{Colors.END}")
                    all_threats.append(f)

        # Summary
        if not all_threats and not scores:
            print(f"  {Colors.GREEN}[CLEAN] No threats detected{Colors.END}")

        # Save rolling report
        duration = (datetime.now() - cycle_start).total_seconds()
        report = {
            "cycle": self.cycle,
            "timestamp": cycle_start.isoformat(),
            "duration_seconds": duration,
            "threats_found": len(all_threats),
            "threats": all_threats,
            "heuristic_scores": scores[:10],
            "watchlist_pids": dict(self.watchlist),
        }

        report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_report.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

    def _handle_threat(self, pid, score):
        """Handle a confirmed threat: attempt to terminate."""
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            print(f"  {Colors.RED}[ACTION] Terminating PID {pid} ({proc_name}) - score {score}/100{Colors.END}")
            proc.terminate()
            proc.wait(timeout=5)
            print(f"  {Colors.GREEN}[KILLED] PID {pid} terminated{Colors.END}")
        except psutil.NoSuchProcess:
            print(f"  {Colors.YELLOW}[INFO] PID {pid} already gone{Colors.END}")
        except psutil.AccessDenied:
            print(f"  {Colors.RED}[FAILED] Access denied for PID {pid} - run as admin{Colors.END}")
        except Exception as e:
            print(f"  {Colors.RED}[FAILED] Could not terminate PID {pid}: {e}{Colors.END}")


if __name__ == "__main__":
    print("=" * 55)
    print("  AV Monitor - Detection Engine Test")
    print("=" * 55)

    # Quick one-time test of each engine
    print(f"\n{Colors.BOLD}[1] Behavioral Analysis{Colors.END}")
    bm = BehavioralMonitor()
    threats = bm.full_check()
    print(f"    Found {len(threats)} behavioral indicators")
    for t in threats:
        print(f"    [{t['severity']}] {t['detail']}")

    print(f"\n{Colors.BOLD}[2] Network Analysis{Colors.END}")
    na = NetworkAnalyzer()
    threats = na.analyze()
    print(f"    Found {len(threats)} network indicators")
    for t in threats:
        print(f"    [{t['severity']}] {t['detail']}")

    print(f"\n{Colors.BOLD}[3] Heuristic Scoring{Colors.END}")
    hs = HeuristicScorer()
    scores = hs.score_all_processes()
    print(f"    Scored {len(scores)} processes with score > 0")
    for s in scores[:5]:
        print(f"    PID {s['pid']} ({s['name']}): {s['score']}/100")
        for r in s['reasons']:
            print(f"      {r}")

    print(f"\n[*] Test complete. Run 'py antivirus.py --monitor' for continuous mode.")
