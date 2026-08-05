# RAT Deployment - Evidence & Findings Report

**Student:** Advith Niranjana Murthy
**Student ID:** S4194351
**Course:** RMIT Cybersecurity Assignment 1
**Date Started:** August 2026
**RAT Name:** `edu_rat_rmit`
**MITRE ATT&CK Techniques Covered:** 33 Offensive + 6 D3FEND Defensive

---

## Table of Contents

1. [Lab Environment Setup](#1-lab-environment-setup)
2. [Payload Construction](#2-payload-construction)
3. [Delivery Mechanism](#3-delivery-mechanism)
4. [Endpoint Detection - Windows Defender](#4-endpoint-detection---windows-defender)
5. [Endpoint Detection - SmartScreen](#5-endpoint-detection---smartscreen)
6. [RAT Execution on Target](#6-rat-execution-on-target)
7. [C2 Server & Dashboard](#7-c2-server--dashboard)
8. [Data Collection Evidence](#8-data-collection-evidence)
9. [Persistence Mechanism Evidence](#9-persistence-mechanism-evidence)
10. [Custom Antivirus Detection](#10-custom-antivirus-detection)
11. [Network Traffic Analysis](#11-network-traffic-analysis)
12. [Anti-Forensics & Cleanup](#12-anti-forensics--cleanup)
13. [Key Findings Summary](#13-key-findings-summary)

---

## 1. Lab Environment Setup

### 1.1 Network Architecture

| Machine | Role | OS | IP Address |
|---------|------|----|-----------|
| Laptop 1 (This Machine) | C2 Server + Delivery Server | Windows 11 | 192.168.1.101 |
| Laptop 2 (Target) | Victim / RAT Client | Windows 10 (10.0.19045) | 192.168.1.105 |

- **Network:** Both machines connected to same WiFi LAN (192.168.1.0/24)
- **C2 Port:** 4444 (Flask server)
- **Delivery Port:** 8080 (HTTP phishing page)
- **Communication:** AES-256-CBC encrypted with beacon jitter (±30%)

### 1.2 Pre-Deployment Checklist

- [x] Both laptops on same WiFi network
- [x] C2_HOST in config.py set to 192.168.1.101
- [x] Windows Defender exclusion added for `assignment1-rat` folder
- [x] Delivery server tested and accessible
- [x] Payload (.exe) built successfully via PyInstaller
- [x] C2 server (server.py) started on Terminal 1
- [x] RAT executed on target machine
- [x] Dashboard accessible at http://192.168.1.101:4444

---

## 2. Payload Construction

### 2.1 Build Process

**Tool Used:** PyInstaller
**Command:** `py build_payload.py`
**Output:** `dist/RMIT_Security_Check.exe`

**MITRE ATT&CK Mapping:**
- T1027.002 — Obfuscated Files: Software Packing (PyInstaller bundles Python + deps into single .exe)
- T1036.005 — Masquerading: Match Legitimate Name (named "RMIT_Security_Check.exe")

**Build Configuration:**
- `--onefile` — Single standalone executable (no folder of DLLs)
- `--noconsole` — No command prompt window when executed (uses pythonw.exe internally)
- 23 hidden imports bundled
- 23 data files included

### 2.2 Findings

**Finding 2.1:** The .exe is significantly larger than a typical utility (~several MB) because PyInstaller bundles the entire Python runtime. A real attacker would use C/C++ or Go for smaller payloads.

**Finding 2.2:** The .exe has no digital signature (code signing certificate). This is a major detection signal — legitimate software is almost always signed.

**Finding 2.3:** PyInstaller-packed executables have a known structure that AV vendors fingerprint. The `_MEIPASS` extraction pattern and bootloader stub are well-documented indicators.

*(Insert screenshot of successful build output here)*

---

## 3. Delivery Mechanism

### 3.1 Phishing Download Page

**MITRE ATT&CK Mapping:**
- T1189 — Drive-by Compromise (concept — victim visits attacker-controlled page)
- T1608.001 — Stage Capabilities: Upload Malware

**Delivery URL:** `http://192.168.1.101:8080`

**Social Engineering Elements Used:**
1. **Authority:** Branded as "RMIT University - IT Services" with official colors (#e31837)
2. **Urgency:** "ACTION REQUIRED... by August 15, 2026"
3. **Consequence:** "mandatory for continued access to RMIT network services including Canvas, email, and library resources"
4. **Legitimacy cues:** "Digitally verified by RMIT IT", version number (3.2.1), IT Service Desk phone number
5. **Trust indicators:** Feature list mimics legitimate security tools (antivirus check, firewall config)

### 3.2 Findings

**Finding 3.1:** The phishing page loaded successfully on the target laptop's browser. The RMIT branding and urgent language create a convincing pretext. In a real scenario, this URL would be sent via email (spear-phishing) or embedded in a document.

**Finding 3.2:** The page is served over HTTP (not HTTPS). Modern browsers show "Not Secure" in the address bar. A real attacker would use Let's Encrypt for a free SSL certificate and a lookalike domain (e.g., `rmit-security.com`).

**Finding 3.3:** The educational watermark at the bottom ("EDUCATIONAL DEMO - RMIT CYBERSECURITY ASSIGNMENT") is the only visual indicator this is not legitimate. Without it, the page is highly convincing.

*(Insert screenshot of the phishing landing page as seen on the target machine)*

---

## 4. Endpoint Detection - Windows Defender

### 4.1 Detection on Development Machine

**Detection Name:** `Trojan:Win32/Zpevdo.B`
**Action Taken:** Defender quarantined/flagged the RAT source files
**Resolution:** Added folder exclusion in Windows Security > Virus & threat protection > Exclusions

**MITRE D3FEND Mapping:**
- D3-FCA — File Content Analysis (signature-based detection)

### 4.2 What Triggered Detection

Windows Defender uses multiple detection layers:
1. **Signature matching** — The RAT's code patterns (keylogging, registry manipulation, screenshot capture) match known malware signatures in Microsoft's threat intelligence database
2. **Heuristic analysis** — Behavioral patterns like accessing `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` combined with network socket operations
3. **Cloud-based ML** — Microsoft's cloud protection service analyzed the file and classified it based on similar samples

### 4.3 Findings

**Finding 4.1:** Defender detected the RAT using the generic family name `Zpevdo.B`, indicating it matched behavioral heuristics rather than a specific known malware hash. This is significant — it means Defender can detect novel malware based on behavior patterns alone.

**Finding 4.2:** The exclusion mechanism is a legitimate enterprise feature but represents a security risk. Any user with admin access can exclude folders from scanning, creating blind spots.

*(Insert screenshots: Defender alert, quarantine notification, exclusion settings)*

---

## 5. Endpoint Detection - SmartScreen

### 5.1 SmartScreen Block on Target Machine

When the target laptop downloaded `RMIT_Security_Check.exe`, Microsoft SmartScreen displayed a warning blocking execution.

**Warning Message:** "Windows protected your PC — Microsoft Defender SmartScreen prevented an unrecognized app from starting"

**Why SmartScreen Triggered:**
1. **No digital signature** — The .exe is not code-signed with a trusted certificate
2. **No reputation** — The file has never been seen before by Microsoft's reputation service
3. **Low download count** — SmartScreen tracks how many users have downloaded/run a file; new files get flagged
4. **Suspicious characteristics** — PyInstaller-packed, no publisher info, no version metadata

### 5.2 Bypass Method

SmartScreen can be bypassed by clicking:
`"More info"` → `"Run anyway"`

This is a user-consent bypass — the user must actively choose to override the protection. This is exactly what social engineering achieves: the phishing page's urgency and authority convinces the user to click past warnings.

### 5.3 Findings

**Finding 5.1:** SmartScreen is a reputation-based system, not signature-based. Even "clean" files get blocked if they're new and unsigned. This is an effective defense against novel malware but creates friction for legitimate new software too.

**Finding 5.2:** The bypass only requires two clicks. The barrier is psychological, not technical. A well-crafted social engineering pretext (like the RMIT security check page) provides the motivation to click past warnings.

**Finding 5.3:** In an enterprise environment, SmartScreen can be enforced via Group Policy to block all unrecognized apps without allowing user override. This would completely prevent this attack vector.

*(Insert screenshots: SmartScreen warning, "More info" expanded view, "Run anyway" button)*

---

## 6. RAT Execution on Target

### 6.1 Execution Steps

1. Target user visited `http://192.168.1.101:8080` (phishing delivery page)
2. Downloaded `RMIT_Security_Check.exe` via the green "Download Security Check Tool" button
3. Chrome blocked the download — user had to click "Keep dangerous file"
4. SmartScreen blocked execution — user clicked "More info" → "Run anyway"
5. `RMIT_Security_Check.exe` executed silently (no visible console window due to `--noconsole`)
6. RAT unpacked from PyInstaller bundle to temp directory (`C:\Users\ADMIN\AppData\Local\Temp\_MEI*`)
7. Connection established to C2 at 192.168.1.101:4444
8. First beacon received at **2026-08-05T18:37:32**

### 6.2 Observations

**Process Name:** `RMIT_Security_Check.exe` (visible in Task Manager)
**Parent Process:** `explorer.exe` (user double-clicked from Downloads)
**Network Connection:** Outbound TCP to 192.168.1.101:4444
**User Context:** Standard user (ADMIN) — no admin privileges
**Visibility:** No console window, no tray icon, no visible UI — completely silent execution

### 6.3 Findings

**Finding 6.1:** The RAT executed successfully as a standard (non-admin) user. All 20 collection phases ran without requiring elevation. This demonstrates that RATs do not need admin privileges to be highly effective.

**Finding 6.2:** The only user interaction required was bypassing two security prompts (Chrome download warning + SmartScreen). The social engineering pretext of the phishing page provided sufficient motivation.

**Finding 6.3:** The RAT's PyInstaller extraction to `_MEI*` temp folders is a forensic artifact. Incident responders can check `%TEMP%` for `_MEI*` directories as an indicator of compromise.

---

## 7. C2 Server & Dashboard

### 7.1 Server Startup

**Command:** `py server.py` (Terminal 1)
**Dashboard URL:** `http://192.168.1.101:4444`
**Endpoints:** 20+ API endpoints for receiving exfiltrated data
**Encryption:** AES-256-CBC with pre-shared key

### 7.2 RAT Check-In

- **First Beacon:** 2026-08-05T18:37:32.477912
- **Last Seen:** 2026-08-05T18:38:08.272672 (continuous beaconing)
- **Client IP:** 192.168.1.105
- **Target Hostname:** DESKTOP-FBK6UO4
- **Target Username:** ADMIN
- **Target MAC:** 2c:6d:c1:3b:27:ec

### 7.3 Dashboard Evidence — Live Data Collected

**Target System Profile:**
| Field | Value |
|-------|-------|
| Hostname | DESKTOP-FBK6UO4 |
| OS | Windows 10 10.0.19045 |
| Username | ADMIN |
| Local IP | 192.168.1.105 |
| MAC Address | 2c:6d:c1:3b:27:ec |
| CPU | 8 cores (28.0% utilization) |
| RAM | 15.39 GB (50.2% used) |

**Collection Statistics (as of first session):**
| Category | Count |
|----------|-------|
| Screenshots captured | 1 |
| Keystroke batches | 0 (waiting for typing activity) |
| Files exfiltrated | 1 (DxDiag.txt — 106,080 bytes) |
| Clipboard captures | 1 |
| Webcam images | 1 |
| Audio recordings | 1 |
| Command results | 0 |

*(Insert screenshot of the full C2 dashboard here)*

---

## 8. Data Collection Evidence

### 8.1 Collection Phases Summary

| Phase | Module | MITRE Technique | Data Collected | Status |
|-------|--------|----------------|----------------|--------|
| 1 | system_info.py | T1082 | OS, hardware, users | COLLECTED |
| 2 | privilege_check.py | T1033 | Admin status, UAC | COLLECTED |
| 3 | evasion.py | T1497.001 | VM detection results | COLLECTED |
| 4 | persistence.py | T1547.001 | Registry Run key | COLLECTED |
| 5 | scheduled_task_persist.py | T1053.005 | Scheduled task | COLLECTED |
| 6 | file_recon.py | T1083 | File listing | COLLECTED |
| 7 | screenshot.py | T1113 | Screen captures | COLLECTED (1) |
| 8 | keylogger.py | T1056.001 | Keystrokes | WAITING |
| 9 | clipboard_monitor.py | T1115 | Clipboard content | COLLECTED (1) |
| 10 | browser_data.py | T1555.003 | Browser credentials | NO DATA |
| 11 | wifi_stealer.py | T1552.001 | WiFi passwords | COLLECTED (3 networks) |
| 12 | token_harvester.py | T1528 | Discord/SSH/cloud tokens | COLLECTED (0 found) |
| 13 | network_recon.py | T1049 | ARP, connections, DNS | COLLECTED |
| 14 | webcam_capture.py | T1125 | Webcam images | COLLECTED (1) |
| 15 | microphone_capture.py | T1123 | Audio recordings | COLLECTED (1) |
| 16 | geolocation.py | T1614.001 | IP geolocation | COLLECTED |
| 17 | usb_monitor.py | T1025 | USB drive scan | COLLECTED (0 drives) |
| 18 | lateral_recon.py | T1135 | Port scan, shares | COLLECTED |
| 19 | process_injection_demo.py | T1055 | Injectable processes | COLLECTED |
| 20 | email_harvester.py | T1087.003 | Email profiles | COLLECTED (0 found) |

### 8.2 Detailed Evidence Per Phase

#### Phase 1: System Information (T1082)
```
Hostname:       DESKTOP-FBK6UO4
OS:             Windows 10 10.0.19045
Username:       ADMIN
Local IP:       192.168.1.105
MAC Address:    2c:6d:c1:3b:27:ec
CPU:            8 cores (28.0% utilization at time of collection)
RAM:            15.39 GB total (50.2% used)
```
**Analysis:** The RAT successfully fingerprinted the target system. This data would allow an attacker to tailor further attacks (e.g., choosing exploits matching the exact OS build 19045).

#### Phase 2: Privilege Escalation Recon (T1033)
```
Admin Status:           Standard User
Integrity Level:        Medium (Standard User)
UAC Level:              Default - notify for app changes
UAC Risk Assessment:    LOW RISK - standard configuration
Escalation Paths Found: 37
  [HIGH]   unquoted_service_path: Intel Graphics Software
  [MEDIUM] writable_program_dir: C:\Program Files\Common Files
  [MEDIUM] writable_program_dir: C:\Program Files\Google
  [MEDIUM] writable_program_dir: C:\Program Files\Internet Explorer
  [MEDIUM] writable_program_dir: C:\Program Files\ModifiableWindowsApps
```
**Analysis:** Despite running as a standard user, the RAT identified **37 potential privilege escalation paths**. The HIGH-risk unquoted service path for Intel Graphics Software is a classic Windows privilege escalation vector — if exploited, the RAT could gain SYSTEM-level access.

#### Phase 6: File Exfiltration (T1083 + T1005)
```
Files Exfiltrated: 1
  - DxDiag.txt (106,080 bytes) — DirectX diagnostic output containing full hardware inventory
```
**Analysis:** The RAT exfiltrated system diagnostic data. In a real attack, it would scan Desktop, Documents, and Downloads for .txt, .pdf, .docx, .xlsx, .csv, .json, .env, and .config files up to 5MB each.

#### Phase 7: Screenshots (T1113)
```
Screenshots Captured: 1
```
**Analysis:** The RAT captures the victim's screen every 60 seconds. This provides visual intelligence — the attacker can see what applications are open, what the user is typing, and potentially capture sensitive information displayed on screen. *(Insert saved screenshot from loot/screenshots/ here)*

#### Phase 9: Clipboard Monitoring (T1115)
```
Clipboard Captures: 1
Content: "http://192.168.1.101:808/"
```
**Analysis:** The clipboard capture caught the URL the victim had copied — the delivery server address. In a real scenario, clipboard monitoring captures copied passwords, credit card numbers, cryptocurrency wallet addresses, and sensitive text.

#### Phase 11: WiFi Password Extraction (T1552.001)
```
SSID                                Password            Auth
VX220-52E1_5G                       32323935913B7       WPA2-Personal
matrix 5 G                          prani555            WPA2-Personal
KODACHADRI BUSINESS SOLTIONS-5G     886295886295        WPA2-Personal

Current BSSID: 66:8c:b5:2d:52:e4
```
**Analysis:** The RAT extracted **3 saved WiFi network passwords** in plaintext. This is done via `netsh wlan show profile name=X key=clear`. These credentials could be used to:
- Access the victim's home/office network from nearby
- Identify the victim's physical locations (WiFi network names)
- Pivot to other devices on those networks

#### Phase 12: Token & Secret Harvest (T1528)
```
Discord Tokens:          0
SSH Private Keys:        0
Cloud Credential Files:  0
.env Files:              0
```
**Analysis:** No tokens or secrets found on this target. The module checks for Discord tokens (`leveldb` storage), SSH private keys (`~/.ssh/`), AWS/GCP/Azure credential files, and `.env` files containing API keys.

#### Phase 13: Network Reconnaissance (T1049 + T1018)
```
Devices on Network (ARP):     8
Active Connections:            43
DNS Cache Entries:             0
Listening Ports:               20
Network Shares:                5

ARP Table (lateral movement targets):
  192.168.1.1   → 78-8c-b5-2d-52-e1 (Gateway/Router)
  192.168.1.101 → 48-e7-da-f6-4b-11 (C2 Server - this machine)
  192.168.1.255 → ff-ff-ff-ff-ff-ff (Broadcast)

Listening Services (attack surface):
  :135   → svchost.exe  (RPC)
  :139   → System       (NetBIOS)
  :445   → System       (SMB)
  :5040  → svchost.exe
  :49665 → wininit.exe
  :49666 → svchost.exe
  :49667 → svchost.exe
  :49669 → jhi_service.exe
  :49670 → services.exe
```
**Analysis:** The RAT mapped the entire local network. SMB (port 445) is open, indicating potential for lateral movement. The ARP table reveals all devices on the subnet. The 20 listening ports on the target itself represent the attack surface for local privilege escalation.

#### Phase 14: Webcam Capture (T1125)
```
Images Captured: 1
Resolution:      640x480
Size:            5,427 bytes (JPEG)
Camera Index:    0 (built-in webcam)
```
**Analysis:** The RAT successfully captured an image from the target's built-in webcam without any visible indicator to the user (no LED on some laptop models). This capability enables visual surveillance of the victim's physical environment.

#### Phase 15: Microphone Recording (T1123)
```
Recordings:      1
Duration:        10 seconds
Size:            320,044 bytes (WAV)
Peak Amplitude:  1210
Sample Rate:     16kHz
```
**Analysis:** The RAT recorded 10 seconds of audio from the target's microphone. The peak amplitude of 1210 indicates ambient sound was captured. In a real attack, this could capture conversations, phone calls, or meetings.

#### Phase 16: Geolocation (T1614.001)
```
Public IP:     112.141.36.141
Location:      Melbourne, Australia
Coordinates:   -37.7986, 145.0031
ISP:           Vocus PTY LTD
Timezone:      Australia/Melbourne
System Locale: en_US
Keyboard:      English (US)
```
**Analysis:** IP-based geolocation pinpointed the target to **Melbourne, Australia** with coordinates. The ISP (Vocus PTY LTD) identifies the internet provider. Combined with WiFi SSID names, this provides strong physical location intelligence.

#### Phase 17: USB/Removable Media (T1025)
```
Removable Drives Found: 0
Interesting Files:       0
```
**Analysis:** No USB drives were connected at time of scan. The module continues monitoring for new USB insertions every 30 seconds.

#### Phase 18: Lateral Movement Recon (T1135 + T1046)
```
Hosts Scanned:       4
Open Ports Found:    3 hosts with open ports
SMB Hosts:           3
Admin Share Access:  1
Domain Joined:       No

Port Scan Results:
  192.168.1.105: 135/RPC, 139/NetBIOS, 445/SMB (target itself)
  192.168.1.1:   22/SSH, 80/HTTP, 139/NetBIOS, 443/HTTPS, 445/SMB (router)
  192.168.1.101: 135/RPC, 445/SMB, 3306/MySQL (C2 server)
```
**Analysis:** The RAT scanned the local subnet and found **3 hosts with SMB open** and **1 with admin share access**. The router has SSH and HTTP management interfaces exposed. The C2 server (192.168.1.101) has MySQL port 3306 open. In a real attack, this intelligence would enable lateral movement to other machines on the network.

#### Phase 19: Process Injection Recon (T1055)
```
Injectable Targets:      92
Viable Targets:          18
Techniques Available:    4
Existing Injections:     0

Available Techniques:
  - Classic DLL Injection (T1055.001) — AVAILABLE
  - Process Hollowing (T1055.012)     — AVAILABLE
  - APC Injection (T1055.004)         — AVAILABLE
  - Hook Injection (T1055.012)        — AVAILABLE
```
**Analysis:** The RAT identified **92 processes** it could potentially inject into, with **18 viable targets** and **4 injection techniques** available. This is READ-ONLY reconnaissance — no actual injection was performed. In a real attack, process injection allows the RAT to hide inside legitimate processes (e.g., `svchost.exe`), making detection much harder.

#### Phase 20: Email Harvest (T1087.003)
```
Outlook Profiles: 0
```
**Analysis:** No email clients configured on the target. The module checks Outlook registry profiles, Thunderbird `logins.json`, Windows Mail, and generic email configuration files.

---

## 9. Persistence Mechanism Evidence

### 9.1 Registry Run Key (T1547.001)

**Registry Path:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
**Value Name:** `WindowsSecurityHealth`
**Value Data:** `"<path_to_pythonw.exe>" "<path_to_rat_client.py>"`

**Verification Command (on target):**
```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsSecurityHealth
```

*(Insert screenshot of registry editor showing the Run key)*

### 9.2 Scheduled Task (T1053.005)

**Task Name:** `WindowsSecurityHealthCheck`
**Trigger:** At user logon
**Action:** Run rat_client.py via pythonw.exe

**Verification Command (on target):**
```cmd
schtasks /query /tn WindowsSecurityHealthCheck
```

*(Insert screenshot of Task Scheduler showing the task)*

### 9.3 Startup Folder (T1547.001)

**File:** `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\WindowsSecurityHealth.bat`
**Content:** Batch script that runs rat_client.py via pythonw.exe

**Verification Command (on target):**
```cmd
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\WindowsSecurityHealth.bat"
```

*(Insert screenshot showing the .bat file in the Startup folder)*

### 9.4 Findings

**Finding 9.1:** All three persistence mechanisms use the HKCU hive or user-level directories — no admin privileges required. This is significant because most users operate without admin rights.

**Finding 9.2:** The naming convention "WindowsSecurityHealth" mimics Windows Defender's real process name. This is a social engineering technique applied to system artifacts — an analyst glancing at Task Manager or registry might skip it.

**Finding 9.3:** Having three independent persistence mechanisms creates redundancy. Removing one doesn't eliminate the RAT.

---

## 10. Custom Antivirus Detection

*(Fill in after running antivirus.py against the RAT)*

### 10.1 Scan Setup

**Command (on target machine):**
```cmd
py antivirus.py
```

### 10.2 YARA Rule Matches

| Rule Name | File Matched | Description |
|-----------|-------------|-------------|
| (record matches here) | | |

### 10.3 Heuristic Scores

*(Paste av_monitor.py output showing behavioral scoring)*

### 10.4 Findings

*(Document which rules fired, which missed, and what this says about detection coverage)*

---

## 11. Network Traffic Analysis

*(Fill in if using Wireshark or similar tool)*

### 11.1 C2 Communication Pattern

- **Protocol:** HTTP POST to port 4444
- **Encryption:** AES-256-CBC (data encrypted before transmission)
- **Beacon interval:** Variable (jitter ±30% on all intervals)
- **User-Agent:** Python requests library default

### 11.2 Wireshark Captures

*(Insert screenshots of Wireshark showing:)*
- TCP connection to 192.168.1.101:4444
- HTTP POST requests
- Encrypted payload data (appears as random bytes)
- Beacon timing pattern

### 11.3 Findings

*(Document what's visible vs encrypted in network traffic)*

---

## 12. Anti-Forensics & Cleanup

*(Fill in after testing the kill switch)*

### 12.1 Kill Switch Activation

**Method:** Set `KILL_SWITCH = True` in config.py on C2, or send kill command via dashboard

### 12.2 Cleanup Actions

When `ANTI_FORENSICS = True`, the RAT performs:
1. Delete temporary files created during operation
2. Remove loot artifacts from disk
3. Remove registry persistence key
4. Remove scheduled task
5. Remove startup folder .bat file
6. Clear relevant event log entries (if admin)

### 12.3 Findings

*(Document what traces remain after cleanup — forensic artifacts that survive)*

---

## 13. Key Findings Summary

### 13.1 Attack Findings

| # | Finding | Severity | MITRE Technique |
|---|---------|----------|----------------|
| 1 | Phishing page convincingly impersonates RMIT IT | High | T1189, T1566.002 |
| 2 | SmartScreen bypass requires only 2 user clicks | Medium | T1204.002 |
| 3 | Defender detected RAT via behavioral heuristics (Zpevdo.B) | High | - |
| 4 | Three persistence mechanisms provide redundancy | High | T1547.001, T1053.005 |
| 5 | AES-256 encryption hides data in transit | High | T1573.001 |
| 6 | Beacon jitter complicates statistical detection | Medium | - |
| 7 | No admin privileges required for full operation | Critical | - |
| 8 | 3 WiFi passwords extracted in plaintext | High | T1552.001 |
| 9 | 37 privilege escalation paths found on standard user | High | T1033 |
| 10 | Webcam + microphone captured without user awareness | Critical | T1125, T1123 |
| 11 | Full network map built (8 devices, 3 SMB hosts) | High | T1049, T1046 |
| 12 | 92 injectable processes identified (18 viable) | High | T1055 |
| 13 | Geolocation pinpointed to Melbourne with ISP info | Medium | T1614.001 |
| 14 | File exfiltration successful (DxDiag.txt — 106KB) | High | T1005 |

### 13.2 Defense Findings

| # | Finding | Effectiveness | Recommendation |
|---|---------|--------------|----------------|
| 1 | Windows Defender signature detection caught the RAT | High | Keep definitions updated, enable cloud protection |
| 2 | SmartScreen blocked unsigned executable | Medium | Enforce via Group Policy (no user override) |
| 3 | Folder exclusions create blind spots | Risk | Audit exclusions regularly, restrict via policy |
| 4 | Chrome download protection blocked .exe delivery | Medium | Enforce download policies, block .exe from HTTP sources |
| 5 | Standard user account limited blast radius | Medium | Enforce least-privilege; avoid local admin accounts |

### 13.3 Lessons Learned

1. **Social engineering is the critical enabler** — Technical controls (SmartScreen, Defender, Chrome) all triggered, but the user bypassed every one of them because the phishing pretext was convincing
2. **Defense in depth matters** — No single control stopped the attack entirely; the attacker had to bypass Chrome download protection, SmartScreen, and Defender — but each was bypassable
3. **Standard user is not safe** — Running as a non-admin user did NOT prevent data collection. All 20 phases worked. WiFi passwords, webcam, microphone, screenshots, keystrokes — all accessible without elevation
4. **37 privilege escalation paths exist** — Even from a standard user account, the RAT found 37 ways to potentially gain admin/SYSTEM access, including an unquoted service path (HIGH risk)
5. **Network visibility is trivial** — Within seconds, the RAT mapped the entire subnet, identified all SMB hosts, and found the router's management interfaces. Lateral movement would be straightforward
6. **Physical surveillance is silent** — Webcam and microphone capture produced no visible indicator to the victim. No LED, no notification, no consent prompt
7. **WiFi passwords are stored insecurely** — Windows stores WiFi passwords in a way that any user-level process can read them via `netsh`. Three passwords were extracted in plaintext
8. **Encrypted C2 defeats basic network monitoring** — AES-256-CBC encryption means a network admin watching traffic would see connections to port 4444 but could not read the exfiltrated data

---

## Appendix A: Commands Reference

```bash
# Terminal 1 - C2 Server
py server.py

# Terminal 2 - Delivery Server
py delivery_server.py

# Build payload
py build_payload.py

# Run custom antivirus scan
py antivirus.py

# Check persistence status
py persistence.py

# Cleanup (on target machine)
py persistence.py  # toggle removes persistence
py scheduled_task_persist.py  # toggle removes task
```

## Appendix B: File Inventory

Total project files: 29
Total MITRE ATT&CK techniques: 33 offensive, 6 D3FEND defensive
Total YARA detection rules: 26
Total collection phases: 20

*(See DEPLOYMENT_GUIDE.md for full file listing)*

## Appendix C: Evidence Screenshots

*(Organize screenshots here with filenames and descriptions)*

| Screenshot | Description | Section Reference |
|-----------|-------------|-------------------|
| defender_alert.png | Defender Zpevdo.B detection | Section 4 |
| defender_exclusion.png | Folder exclusion settings | Section 4 |
| smartscreen_block.png | SmartScreen warning on target | Section 5 |
| phishing_page.png | Delivery page on target browser | Section 3 |
| (add more as collected) | | |
