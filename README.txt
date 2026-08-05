EDUCATIONAL RAT - RMIT CYBERSECURITY ASSIGNMENT
================================================
For academic demonstration only. Do NOT use on unauthorized systems.

PROJECT STRUCTURE (20 files)
----------------------------
WINDOWS (Your PC - Attack Side):
  config.py              - Configuration (SET YOUR KALI IP HERE)
  rat_client.py          - Main RAT controller (13 phases + jitter + anti-forensics)
  system_info.py         - System info gathering (T1082)
  file_recon.py          - File discovery & exfiltration (T1083, T1005)
  screenshot.py          - Screen capture (T1113)
  keylogger.py           - Keystroke capture (T1056.001)
  crypto_utils.py        - AES-256-CBC encryption for C2 comms (T1573.001)
  evasion.py             - VM detection + console hide + masquerade (T1497.001, T1036, T1564.003)
  persistence.py         - Registry Run key persistence (T1547.001)
  clipboard_monitor.py   - Clipboard capture (T1115)
  browser_data.py        - Chrome/Edge credential & history theft (T1555.003)
  privilege_check.py     - Privilege recon + UAC + escalation paths (T1033, T1548.002)
  wifi_stealer.py        - Wi-Fi password extraction via netsh (T1552.001)
  token_harvester.py     - Discord tokens, SSH keys, cloud creds, .env files (T1528)
  network_recon.py       - ARP table, connections, DNS cache, shares (T1049, T1018)
  lateral_recon.py       - Port scanning, share enum, domain recon, admin shares (T1135, T1046) [NEW]
  event_log_tamper.py    - Event log enumeration + clearing (T1070.001, T1562.002) [NEW]

KALI VM (Listener Side):
  server.py              - C2 listener + web dashboard (decrypts AES, remote shell)

DEFENSE:
  antivirus.py           - Custom RAT detector + killer (8 scan methods)
  av_signatures.py       - YARA-style signature rule engine (18 rules) [UPDATED: +3 rules]
  av_monitor.py          - Behavioral/memory/network/heuristic engines [UPDATED]

EDUCATIONAL REFERENCE:
  delivery_demo.py       - 4 delivery methods with real-world examples
  phishing_email.html    - Annotated phishing email with red flags


SETUP INSTRUCTIONS
------------------

STEP 1: Set VirtualBox Network
  - Open VirtualBox > Your Kali VM > Settings > Network
  - Set Adapter 1 to "Host-Only Adapter"
  - Start Kali VM

STEP 2: Get Kali IP
  - In Kali terminal: ip addr
  - Look for the IP on the host-only interface (usually 192.168.56.x)

STEP 3: Update config.py
  - Change C2_HOST = "CHANGE_ME" to your Kali IP
  - e.g., C2_HOST = "192.168.56.101"

STEP 4: Copy server.py + crypto_utils.py to Kali
  - Both files needed (server.py imports crypto_utils.py for decryption)
  - From Windows: copy to shared folder, or use SCP

STEP 5a: Install dependencies (on Kali)
  - pip3 install flask flask-cors pycryptodome

STEP 5b: Install dependencies (on Windows)
  - pip install pycryptodome pywin32

STEP 6: Start C2 Listener (on Kali)
  - cd to the folder with server.py
  - python3 server.py
  - Open browser: http://localhost:4444

STEP 7: Run RAT (on Windows)
  - Open terminal in this folder
  - py rat_client.py
  - Watch data flow to the Kali dashboard
  - All 13 phases execute: sysinfo -> files -> screenshots -> keylogger
    -> clipboard -> browser creds -> privilege recon -> wifi passwords
    -> token harvest -> network recon -> lateral recon -> event logs
    -> remote commands
  - Note: C2 beacon jitter is ON by default (±30% timing randomization)

STEP 8: Run Antivirus (on Windows - new terminal)
  - py antivirus.py              (one-time 8-method scan + 18 YARA rules)
  - py antivirus.py --monitor    (continuous monitoring mode)
  - Watch it detect and kill the RAT

STEP 9: Demo Complete!
  - Show the C2 dashboard with all collected data types
  - Show Wi-Fi passwords, Discord tokens, SSH keys on the dashboard
  - Show network topology (ARP table, DNS cache, listening ports)
  - Show lateral recon (port scan, SMB shares, admin access, domain info)
  - Show event log enumeration (forensic evidence inventory)
  - Show encrypted traffic in Wireshark (gibberish vs plaintext)
  - Show the antivirus scan report (8 detection methods + 15 YARA rules)
  - Show the kill switch feature (activates anti-forensics cleanup)
  - Show persistence: reboot Windows, RAT auto-starts
  - Run py persistence.py to clean up registry after demo


DEMO FLOW (Recommended Order)
------------------------------
1. Start C2 listener on Kali (python3 server.py)
2. Open dashboard in browser (http://kali-ip:4444)
3. Run RAT on Windows (py rat_client.py)
4. Watch dashboard populate: system info, files, screenshots, keystrokes,
   clipboard, browser creds, privilege info, Wi-Fi passwords, tokens,
   network map, lateral movement recon, event log status
5. Use remote shell from dashboard to execute commands
6. Open Wireshark on Kali - show encrypted traffic (AES-256-CBC)
7. Point out beacon jitter: connection intervals are randomized ±30%
8. Activate kill switch from dashboard - watch anti-forensics cleanup
9. Run antivirus (py antivirus.py) - show 8 detection methods + 18 YARA rules
10. Run continuous monitor (py antivirus.py --monitor) - show real-time detection
11. Show persistence cleanup (py persistence.py)
12. Run delivery_demo.py and open phishing_email.html to discuss social engineering


STANDALONE MODULE TESTS
------------------------
  py crypto_utils.py       - AES encrypt/decrypt round-trip test
  py evasion.py            - VM detection results
  py persistence.py        - Registry key write/read/delete test
  py clipboard_monitor.py  - Clipboard capture test (30 seconds)
  py browser_data.py       - Browser password/history extraction
  py privilege_check.py    - Admin status, UAC, escalation paths
  py wifi_stealer.py       - Wi-Fi password extraction test [NEW]
  py token_harvester.py    - Discord/SSH/cloud/env file harvesting [NEW]
  py network_recon.py      - Network topology mapping
  py lateral_recon.py      - Lateral movement recon (port scan, shares, domain) [NEW]
  py event_log_tamper.py   - Event log enumeration (read-only by default) [NEW]
  py av_signatures.py      - YARA rule scan of all .py files (18 rules)
  py av_monitor.py         - One-time test of all detection engines


HIDDEN FEATURES (What makes this RAT interesting)
--------------------------------------------------
1. BEACON JITTER: All C2 intervals are randomized ±30% to defeat the AV's
   beacon detection (which checks for std_dev < 5s). Real C2 frameworks
   (Cobalt Strike, Sliver) use the same technique. Toggle: BEACON_JITTER=True

2. ANTI-FORENSICS: Kill switch triggers evidence cleanup — removes temp files,
   persistence artifacts, __pycache__. Real APTs always clean up.
   Toggle: ANTI_FORENSICS=True

3. WI-FI PASSWORDS: Goes beyond just listing SSIDs (which system_info.py does).
   Extracts actual cleartext passwords via 'netsh wlan show profile key=clear'.
   Combined with BSSID, this enables physical location correlation.

4. DISCORD TOKEN THEFT: Searches LevelDB in 7 browser/app paths for Discord
   auth tokens. A valid token bypasses MFA entirely — full account takeover.
   This is exactly how RedLine/Lumma/Vidar stealers work.

5. SSH KEY HARVESTING: Finds private keys in ~/.ssh/, checks if they have a
   passphrase (many don't), and maps known_hosts for server inventory. One
   unprotected key = access to every server it's authorized for.

6. CLOUD CREDENTIAL THEFT: Checks 12 well-known paths for AWS/Azure/GCP/K8s
   credentials. A single leaked AWS key has caused $100K+ crypto mining bills.
   Also checks .git-credentials, .npmrc, .pypirc for supply chain attacks.

7. .ENV FILE SCANNER: Walks dev directories (3 levels deep) looking for .env
   files with API keys, database passwords, JWT secrets. Uses regex to identify
   and catalog secret types.

8. DNS CACHE AS BROWSING HISTORY: ipconfig /displaydns reveals every domain
   the machine recently resolved — effectively browsing history without needing
   browser access. Works even in incognito mode.

9. NETWORK TOPOLOGY MAPPING: ARP table reveals all devices on the LAN. Combined
   with listening services and SMB shares, this maps the entire local attack
   surface for lateral movement planning.

10. LATERAL MOVEMENT RECON: After mapping the network (Phase 11), Phase 12
    scans discovered hosts for open SMB/RDP/SSH/WinRM ports, enumerates
    accessible file shares, checks for admin share access (C$/ADMIN$),
    discovers domain membership and domain controllers. This is how APTs
    plan their campaign after initial compromise.

11. EVENT LOG TAMPERING: Phase 13 enumerates all Windows event logs
    (Security, System, PowerShell, Sysmon, etc.), counts forensic evidence,
    and can optionally clear them. Clearing logs generates Event ID 1102/104
    — so even clearing itself leaves evidence (recursive problem). Disabled
    by default (CLEAR_EVENT_LOGS=False in config.py).

12. ARMS RACE DESIGN: Each new offensive feature has matching AV detection:
    18 YARA rules + updated memory signatures + heuristic scoring rules.
    This demonstrates the real-world cat-and-mouse between attackers and defenders.


MITRE ATT&CK MAPPING (25 Techniques)
--------------------------------------
Offense:
  T1082     - System Information Discovery         (system_info.py)
  T1083     - File and Directory Discovery          (file_recon.py)
  T1005     - Data from Local System                (file_recon.py)
  T1113     - Screen Capture                        (screenshot.py)
  T1056.001 - Input Capture: Keylogging             (keylogger.py)
  T1041     - Exfiltration Over C2 Channel          (rat_client.py)
  T1059.006 - Command and Scripting: Python         (rat_client.py)
  T1573.001 - Encrypted Channel: Symmetric Crypto   (crypto_utils.py)
  T1547.001 - Boot/Logon Autostart: Registry Run    (persistence.py)
  T1497.001 - Virtualization/Sandbox Evasion        (evasion.py)
  T1036     - Masquerading                          (evasion.py)
  T1564.003 - Hide Artifacts: Hidden Window         (evasion.py)
  T1115     - Clipboard Data                        (clipboard_monitor.py)
  T1555.003 - Credentials from Web Browsers         (browser_data.py)
  T1059.003 - Command and Scripting: Windows Shell  (rat_client.py)
  T1033     - System Owner/User Discovery           (privilege_check.py)
  T1552.001 - Unsecured Credentials In Files        (wifi_stealer.py, token_harvester.py)
  T1528     - Steal Application Access Token         (token_harvester.py)
  T1049     - System Network Connections Discovery   (network_recon.py)
  T1018     - Remote System Discovery                (network_recon.py)
  T1016     - System Network Configuration Discovery (network_recon.py)
  T1070.004 - Indicator Removal: File Deletion       (rat_client.py)
  T1135     - Network Share Discovery                (lateral_recon.py) [NEW]
  T1046     - Network Service Scanning               (lateral_recon.py) [NEW]
  T1070.001 - Indicator Removal: Clear Event Logs    (event_log_tamper.py) [NEW]

Delivery/Social Engineering (delivery_demo.py + phishing_email.html):
  T1566.001 - Phishing: Spearphishing Attachment
  T1204.002 - User Execution: Malicious File
  T1036.005 - Masquerading: Match Legitimate Name

MITRE D3FEND (Defense - 6 Techniques):
  D3-PM  - Process Monitoring                       (antivirus.py)
  D3-NTA - Network Traffic Analysis                 (antivirus.py + av_monitor.py)
  D3-FH  - File Hashing                            (antivirus.py)
  D3-FSB - File Content Signature-Based             (av_signatures.py — 15 rules)
  D3-MA  - Memory Analysis                          (av_monitor.py)
  D3-BAN - Behavioral Analysis                      (av_monitor.py)
