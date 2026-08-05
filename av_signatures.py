"""
YARA-Style Signature Rule Engine (Pure Python)
MITRE D3FEND: D3-FSB (File Content Signature-Based)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Lightweight signature scanner that checks file contents against
predefined rules. Each rule has strings to match and a condition
(e.g., "any 2 of", "all of"). No C dependencies (no real YARA needed).
"""


# ============ SIGNATURE RULES ============

RULES = [
    {
        "name": "RAT_C2_Communication",
        "severity": "CRITICAL",
        "mitre": "T1041",
        "description": "Detects C2 communication patterns in RAT code",
        "strings": {
            "$c2_host": "C2_HOST",
            "$send_fn": "send_to_c2",
            "$exfil": "exfiltrate",
            "$port": "4444",
        },
        "condition": "any 2 of",
    },
    {
        "name": "RAT_Keylogger",
        "severity": "CRITICAL",
        "mitre": "T1056.001",
        "description": "Detects keylogger components",
        "strings": {
            "$pynput": "pynput",
            "$on_press": "on_press",
            "$keystroke": "keystroke",
            "$log_buffer": "log_buffer",
        },
        "condition": "any 2 of",
    },
    {
        "name": "RAT_Screenshot",
        "severity": "HIGH",
        "mitre": "T1113",
        "description": "Detects screenshot capture capabilities",
        "strings": {
            "$imagegrab_import": "ImageGrab",
            "$imagegrab_call": "ImageGrab.grab",
            "$image_b64": "image_b64",
        },
        "condition": "any 2 of",
    },
    {
        "name": "RAT_Persistence_Registry",
        "severity": "CRITICAL",
        "mitre": "T1547.001",
        "description": "Detects registry-based persistence mechanisms",
        "strings": {
            "$winreg": "winreg",
            "$run_key": "CurrentVersion\\Run",
            "$set_value": "SetValueEx",
        },
        "condition": "any 2 of",
    },
    {
        "name": "RAT_Encrypted_C2",
        "severity": "HIGH",
        "mitre": "T1573.001",
        "description": "Detects encrypted C2 communication setup",
        "strings": {
            "$aes": "AES",
            "$encrypt_fn": "encrypt_payload",
            "$decrypt_fn": "decrypt_payload",
            "$passphrase": "C2_PASSPHRASE",
        },
        "condition": "any 2 of",
    },
    {
        "name": "RAT_Browser_Credential_Theft",
        "severity": "CRITICAL",
        "mitre": "T1555.003",
        "description": "Detects browser credential extraction code",
        "strings": {
            "$login_data": "Login Data",
            "$crypt_unprotect": "CryptUnprotectData",
            "$local_state": "Local State",
            "$chrome_path": "Chrome\\User Data",
        },
        "condition": "any 2 of",
    },
    {
        "name": "RAT_Clipboard_Capture",
        "severity": "MEDIUM",
        "mitre": "T1115",
        "description": "Detects clipboard monitoring capabilities",
        "strings": {
            "$get_clipboard": "GetClipboardData",
            "$win32clip": "win32clipboard",
            "$open_clipboard": "OpenClipboard",
        },
        "condition": "any 2 of",
    },
    {
        "name": "RAT_VM_Evasion",
        "severity": "MEDIUM",
        "mitre": "T1497.001",
        "description": "Detects VM/sandbox evasion techniques",
        "strings": {
            "$virtualbox": "VirtualBox",
            "$vmware": "vmware",
            "$detect_fn": "detect_virtual",
            "$wmi_check": "Win32_ComputerSystem",
        },
        "condition": "any 2 of",
    },
    {
        "name": "RAT_WiFi_Password_Theft",
        "severity": "HIGH",
        "mitre": "T1552.001",
        "description": "Detects Wi-Fi password extraction via netsh",
        "strings": {
            "$netsh_cmd": "netsh",
            "$wlan_show": "wlan",
            "$key_clear": "key=clear",
            "$key_content": "Key Content",
        },
        "condition": "any 3 of",
    },
    {
        "name": "RAT_Discord_Token_Theft",
        "severity": "CRITICAL",
        "mitre": "T1528",
        "description": "Detects Discord token harvesting from LevelDB",
        "strings": {
            "$discord_path": "discord",
            "$leveldb": "leveldb",
            "$token_regex": "mfa\\.",
            "$local_storage": "Local Storage",
        },
        "condition": "any 3 of",
    },
    {
        "name": "RAT_SSH_Key_Theft",
        "severity": "CRITICAL",
        "mitre": "T1552.001",
        "description": "Detects SSH private key harvesting",
        "strings": {
            "$ssh_dir": ".ssh",
            "$rsa_key": "BEGIN RSA PRIVATE KEY",
            "$openssh_key": "BEGIN OPENSSH PRIVATE KEY",
            "$known_hosts": "known_hosts",
        },
        "condition": "any 2 of",
    },
    {
        "name": "RAT_Cloud_Credential_Theft",
        "severity": "CRITICAL",
        "mitre": "T1552.001",
        "description": "Detects cloud CLI credential harvesting (AWS/Azure/GCP)",
        "strings": {
            "$aws_creds": ".aws",
            "$azure_creds": ".azure",
            "$gcloud_creds": "gcloud",
            "$kube_config": ".kube",
            "$credentials": "credentials",
        },
        "condition": "any 3 of",
    },
    {
        "name": "RAT_Network_Reconnaissance",
        "severity": "HIGH",
        "mitre": "T1049",
        "description": "Detects network topology mapping and reconnaissance",
        "strings": {
            "$arp_cmd": "arp",
            "$dns_cache": "displaydns",
            "$net_share": "net share",
            "$net_connections": "net_connections",
        },
        "condition": "any 2 of",
    },
    {
        "name": "RAT_Anti_Forensics",
        "severity": "HIGH",
        "mitre": "T1070.004",
        "description": "Detects anti-forensics and evidence destruction",
        "strings": {
            "$anti_forensics": "anti_forensics",
            "$remove_persist": "remove_persistence",
            "$rmtree": "rmtree",
            "$quarantined": "quarantined",
        },
        "condition": "any 2 of",
    },
    {
        "name": "RAT_Beacon_Jitter",
        "severity": "MEDIUM",
        "mitre": "T1029",
        "description": "Detects C2 beacon timing randomization (jitter)",
        "strings": {
            "$jitter": "jitter",
            "$random_uniform": "random.uniform",
            "$beacon": "BEACON_JITTER",
            "$jitter_percent": "JITTER_PERCENT",
        },
        "condition": "any 2 of",
    },
    {
        "name": "RAT_Lateral_Movement_Recon",
        "severity": "HIGH",
        "mitre": "T1135",
        "description": "Detects network share discovery and lateral movement reconnaissance",
        "strings": {
            "$net_view": "net view",
            "$admin_share": "ADMIN$",
            "$scan_port": "scan_port",
            "$smb_hosts": "smb_hosts",
        },
        "condition": "any 2 of",
    },
    {
        "name": "RAT_Port_Scanner",
        "severity": "HIGH",
        "mitre": "T1046",
        "description": "Detects network service scanning capabilities",
        "strings": {
            "$connect_ex": "connect_ex",
            "$scan_host": "scan_host_ports",
            "$sock_stream": "SOCK_STREAM",
            "$thread_pool": "ThreadPoolExecutor",
        },
        "condition": "any 2 of",
    },
    {
        "name": "RAT_Event_Log_Tampering",
        "severity": "CRITICAL",
        "mitre": "T1070.001",
        "description": "Detects Windows event log clearing and tampering",
        "strings": {
            "$wevtutil_cl": "wevtutil",
            "$clear_log": "clear_event_log",
            "$security_evtx": "Security",
            "$clear_forensic": "clear_forensic",
        },
        "condition": "any 2 of",
    },
    # ===== NEW RULES FOR PHASE 14-20 FEATURES =====
    {
        "name": "RAT_Webcam_Capture",
        "severity": "CRITICAL",
        "mitre": "T1125",
        "description": "Detects webcam video capture capabilities",
        "strings": {
            "$cv2_import": "cv2",
            "$videocapture": "VideoCapture",
            "$cap_dshow": "CAP_DSHOW",
            "$imencode": "imencode",
        },
        "condition": "any 2 of",
    },
    {
        "name": "RAT_Microphone_Capture",
        "severity": "CRITICAL",
        "mitre": "T1123",
        "description": "Detects microphone audio recording capabilities",
        "strings": {
            "$sounddevice": "sounddevice",
            "$sd_rec": "sd.rec",
            "$wave_open": "wave.open",
            "$audio_b64": "audio_b64",
        },
        "condition": "any 2 of",
    },
    {
        "name": "RAT_Scheduled_Task_Persistence",
        "severity": "CRITICAL",
        "mitre": "T1053.005",
        "description": "Detects scheduled task creation for persistence",
        "strings": {
            "$schtasks_create": "schtasks /Create",
            "$onlogon": "ONLOGON",
            "$task_name": "WindowsSecurityHealth",
            "$schtasks_delete": "schtasks /Delete",
        },
        "condition": "any 2 of",
    },
    {
        "name": "RAT_Startup_Folder_Persistence",
        "severity": "HIGH",
        "mitre": "T1547.001",
        "description": "Detects startup folder persistence via .bat file",
        "strings": {
            "$startup_path": "Start Menu\\Programs\\Startup",
            "$bat_file": "WindowsSecurityHealth.bat",
            "$echo_off": "@echo off",
            "$pythonw": "pythonw",
        },
        "condition": "any 2 of",
    },
    {
        "name": "RAT_USB_Monitor",
        "severity": "HIGH",
        "mitre": "T1025",
        "description": "Detects USB/removable media scanning and monitoring",
        "strings": {
            "$get_drive_type": "GetDriveTypeW",
            "$drive_removable": "DRIVE_REMOVABLE",
            "$get_logical": "GetLogicalDrives",
            "$removable_drives": "removable_drives",
        },
        "condition": "any 2 of",
    },
    {
        "name": "RAT_Geolocation",
        "severity": "MEDIUM",
        "mitre": "T1016",
        "description": "Detects IP-based geolocation reconnaissance",
        "strings": {
            "$ip_api": "ip-api.com",
            "$ipinfo": "ipinfo.io",
            "$geolocation": "geolocation",
            "$latitude": "latitude",
        },
        "condition": "any 2 of",
    },
    {
        "name": "RAT_Process_Injection_Recon",
        "severity": "CRITICAL",
        "mitre": "T1055",
        "description": "Detects process injection capability assessment",
        "strings": {
            "$virtual_alloc": "VirtualAllocEx",
            "$write_process": "WriteProcessMemory",
            "$create_remote": "CreateRemoteThread",
            "$hollow": "Process Hollowing",
        },
        "condition": "any 2 of",
    },
    {
        "name": "RAT_Email_Harvester",
        "severity": "HIGH",
        "mitre": "T1087.003",
        "description": "Detects email credential and profile harvesting",
        "strings": {
            "$outlook_profiles": "Outlook\\Profiles",
            "$thunderbird": "Thunderbird",
            "$logins_json": "logins.json",
            "$prefs_js": "prefs.js",
        },
        "condition": "any 2 of",
    },
]


# ============ MATCHING ENGINE ============

def match_rule(content, rule):
    """
    Evaluate a single rule against file content.

    Args:
        content: File content as string
        rule: Rule dict with strings and condition

    Returns:
        dict with rule name, matched strings, offsets — or None if no match
    """
    matched = {}

    for var_name, pattern in rule["strings"].items():
        offset = content.find(pattern)
        if offset != -1:
            matched[var_name] = {
                "pattern": pattern,
                "offset": offset,
            }

    # Evaluate condition
    condition = rule["condition"]
    total_strings = len(rule["strings"])
    matched_count = len(matched)

    triggered = False

    if condition == "all of":
        triggered = matched_count == total_strings
    elif condition.startswith("any"):
        # Parse "any N of" or just "any of"
        parts = condition.split()
        if len(parts) == 3 and parts[1].isdigit():
            threshold = int(parts[1])
        else:
            threshold = 1
        triggered = matched_count >= threshold

    if triggered:
        return {
            "rule": rule["name"],
            "severity": rule["severity"],
            "mitre": rule["mitre"],
            "description": rule["description"],
            "matched_strings": matched,
            "matched_count": matched_count,
            "total_strings": total_strings,
        }

    return None


def scan_content(content):
    """
    Run all signature rules against content.

    Args:
        content: File content as string

    Returns:
        list of match dicts (one per triggered rule)
    """
    matches = []
    for rule in RULES:
        result = match_rule(content, rule)
        if result:
            matches.append(result)
    return matches


def scan_file(filepath):
    """
    Scan a single file against all rules.

    Args:
        filepath: Path to file to scan

    Returns:
        list of match dicts, or empty list
    """
    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
        return scan_content(content)
    except Exception:
        return []


if __name__ == "__main__":
    import os

    print("=" * 55)
    print("  YARA-Style Signature Scanner")
    print(f"  {len(RULES)} rules loaded")
    print("=" * 55)

    # Scan all .py files in current directory
    scan_dir = os.path.dirname(os.path.abspath(__file__))
    py_files = [f for f in os.listdir(scan_dir) if f.endswith(".py")]

    total_matches = 0
    for fname in sorted(py_files):
        fpath = os.path.join(scan_dir, fname)
        matches = scan_file(fpath)
        if matches:
            print(f"\n  [{len(matches)} HIT(S)] {fname}:")
            for m in matches:
                print(f"    [{m['severity']}] {m['rule']} ({m['mitre']})")
                print(f"      Matched: {m['matched_count']}/{m['total_strings']} strings")
                for var, info in m["matched_strings"].items():
                    print(f"        {var} = \"{info['pattern']}\" at offset {info['offset']}")
                total_matches += 1

    print(f"\n{'='*55}")
    print(f"  Scanned {len(py_files)} files, {total_matches} rule triggers")
    print(f"{'='*55}")
