================================================================
  EDUCATIONAL RAT - DEPLOYMENT & OPERATION GUIDE
  RMIT Cybersecurity Assignment
  33 MITRE ATT&CK Techniques | 26 YARA Detection Rules
================================================================

ARCHITECTURE
------------
  Windows Machine (Victim)  ──── HTTP POST (port 4444) ────>  Kali VM (C2 Listener)
  rat_client.py                                                server.py
  antivirus.py                                                 Dashboard :4444

  Network: VirtualBox Host-Only Adapter (192.168.56.0/24)
  Windows Host IP: 192.168.56.1
  Kali VM IP: 192.168.56.x (find with: ip addr show eth1)


================================================================
  STEP-BY-STEP DEPLOYMENT
================================================================

STEP 1: START KALI VM
  - Open VirtualBox
  - Start "kali-linux-2025.2-virtualbox-amd64"
  - Login (default: kali / kali)

STEP 2: GET KALI IP
  In Kali terminal:
    ip addr show eth1

  If no IP on eth1, set one manually:
    sudo ip addr add 192.168.56.101/24 dev eth1
    sudo ip link set eth1 up

  Verify connectivity from Windows:
    ping 192.168.56.101

STEP 3: UPDATE CONFIG ON WINDOWS
  Edit config.py line 7:
    C2_HOST = "192.168.56.101"    <-- replace with your Kali IP

STEP 4: COPY SERVER FILES TO KALI
  From Windows PowerShell:
    scp "C:\Users\91636\Desktop\assignment1-rat\server.py" kali@192.168.56.101:~/
    scp "C:\Users\91636\Desktop\assignment1-rat\crypto_utils.py" kali@192.168.56.101:~/

  Or use a shared folder / USB to transfer.

STEP 5: INSTALL DEPENDENCIES

  On Kali:
    pip3 install flask flask-cors pycryptodome

  On Windows (if not already done):
    pip install pycryptodome pywin32 psutil pynput Pillow requests opencv-python sounddevice numpy

STEP 6: START C2 LISTENER (KALI)
    cd ~
    python3 server.py

  Dashboard opens at: http://192.168.56.101:4444
  You should see "Waiting for RAT connection..."

STEP 7: LAUNCH RAT (WINDOWS)
    cd C:\Users\91636\Desktop\assignment1-rat
    py rat_client.py

  All 20 phases will execute automatically.
  Data streams to the Kali dashboard in real time.

STEP 8: RUN ANTIVIRUS (SEPARATE WINDOWS TERMINAL)
    cd C:\Users\91636\Desktop\assignment1-rat
    py antivirus.py              (one-time 8-method scan)
    py antivirus.py --monitor    (continuous monitoring mode)

STEP 9: CLEANUP WHEN DONE
  Option A: Click "ACTIVATE KILL SWITCH" on the Kali dashboard
  Option B: Press Ctrl+C on the Windows RAT terminal

  Kill switch removes all 3 persistence mechanisms:
    - Registry Run key
    - Scheduled task
    - Startup folder .bat


================================================================
  FILE INVENTORY (29 Python files)
================================================================

OFFENSE (Windows RAT Client - 24 files):
  rat_client.py            Main controller (20 phases, 7 threads)
  config.py                All settings and toggles
  system_info.py           System recon (T1082)
  file_recon.py            File discovery + exfil (T1083, T1005)
  screenshot.py            Screen capture (T1113)
  keylogger.py             Keystroke capture (T1056.001)
  clipboard_monitor.py     Clipboard monitoring (T1115)
  browser_data.py          Chrome/Edge passwords + history (T1555.003)
  privilege_check.py       Admin check + UAC + escalation paths (T1033)
  wifi_stealer.py          Wi-Fi password extraction (T1552.001)
  token_harvester.py       Discord/SSH/Cloud/.env secrets (T1528)
  network_recon.py         ARP, DNS cache, connections, shares (T1049)
  lateral_recon.py         Port scan, SMB shares, domain info (T1135, T1046)
  event_log_tamper.py      Event log enumeration + clearing (T1070.001)
  webcam_capture.py        Webcam image capture (T1125)
  microphone_capture.py    Audio recording (T1123)
  usb_monitor.py           USB/removable media scanning (T1025)
  geolocation.py           IP geolocation + locale (T1016, T1614.001)
  process_injection_demo.py  Injection recon - READ ONLY (T1055)
  email_harvester.py       Outlook/Thunderbird/Mail profiles (T1087.003)
  persistence.py           Registry Run key persistence (T1547.001)
  scheduled_task_persist.py  Sched task + startup folder (T1053.005)
  evasion.py               VM detection, console hiding (T1497.001)
  crypto_utils.py          AES-256-CBC encryption (T1573.001)

DEFENSE (Kali C2 Server - 2 files):
  server.py                Flask C2 listener + web dashboard
  crypto_utils.py          AES-256-CBC decryption (shared)

ANTIVIRUS (Windows Defense - 3 files):
  antivirus.py             Main AV engine (8 detection methods)
  av_signatures.py         26 YARA-style signature rules
  av_monitor.py            Behavioral, memory, network, heuristic engines

EDUCATIONAL REFERENCE (2 files):
  delivery_demo.py         4 delivery method explanations
  phishing_email.html      Annotated phishing email example


================================================================
  20 COLLECTION PHASES
================================================================

ONE-TIME PHASES (run once at startup):
  Phase 1:  System info (hostname, OS, IP, CPU, RAM, processes)
  Phase 2:  File recon (directory tree + exfiltrate first 10 files)
  Phase 6:  Browser passwords + history (Chrome, Edge)
  Phase 7:  Privilege recon (admin check, UAC, escalation paths)
  Phase 9:  Wi-Fi passwords (all saved profiles)
  Phase 10: Token harvest (Discord, SSH keys, cloud creds, .env)
  Phase 11: Network recon (ARP, DNS cache, connections, shares)
  Phase 12: Lateral recon (port scan, SMB, domain info)
  Phase 13: Event log enumeration
  Phase 16: Geolocation (IP location, locale, timezone)
  Phase 17: USB/removable media scan
  Phase 19: Process injection recon (read-only)
  Phase 20: Email profile harvest

CONTINUOUS PHASES (run as background threads):
  Phase 3:  Screenshots (every 60s ±30% jitter)
  Phase 4:  Keylogger (every 30s batches)
  Phase 5:  Clipboard capture (every 10s)
  Phase 8:  Remote command polling (every 15s)
  Phase 14: Webcam capture (every 120s)
  Phase 15: Microphone recording (10s clips every 180s)
  Phase 18: USB insertion monitor (every 30s)


================================================================
  PERSISTENCE MECHANISMS (3 methods)
================================================================

1. Registry Run Key (T1547.001)
   HKCU\Software\Microsoft\Windows\CurrentVersion\Run
   Value: "WindowsSecurityHealth" -> pythonw.exe rat_client.py
   No admin required.

2. Scheduled Task (T1053.005)
   Name: "WindowsSecurityHealthCheck"
   Trigger: User logon with 60-second delay
   No admin required.

3. Startup Folder (T1547.001)
   %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\WindowsSecurityHealth.bat
   Launches pythonw.exe on logon.


================================================================
  ANTIVIRUS DETECTION (8 methods + 26 YARA rules)
================================================================

Scan 1: Process detection (known RAT script names in cmdline)
Scan 2: Network detection (connections to port 4444)
Scan 3: YARA file signatures (26 rules across all .py files)
Scan 4: Persistence detection (registry + scheduled task + startup folder)
Scan 5: Memory scanning (C2 URLs, known strings in process memory)
Scan 6: Behavioral analysis (registry diffs, keylogger patterns)
Scan 7: Advanced network (beacon detection, data volume)
Scan 8: Heuristic scoring (0-100 per process, auto-kill at 75+)


================================================================
  MITRE ATT&CK COVERAGE (33 offensive + 6 defensive)
================================================================

OFFENSIVE:
  T1082     System Information Discovery
  T1083     File and Directory Discovery
  T1005     Data from Local System
  T1113     Screen Capture
  T1056.001 Input Capture: Keylogging
  T1041     Exfiltration Over C2 Channel
  T1059.006 Command and Scripting: Python
  T1059.003 Command and Scripting: Windows Command Shell
  T1573.001 Encrypted Channel: Symmetric Cryptography
  T1547.001 Boot/Logon Autostart: Registry Run Keys + Startup Folder
  T1053.005 Scheduled Task/Job: Scheduled Task
  T1497.001 Virtualization/Sandbox Evasion
  T1036     Masquerading
  T1564.003 Hide Artifacts: Hidden Window
  T1115     Clipboard Data
  T1555.003 Credentials from Web Browsers
  T1033     System Owner/User Discovery
  T1552.001 Unsecured Credentials: Credentials In Files
  T1528     Steal Application Access Token
  T1049     System Network Connections Discovery
  T1018     Remote System Discovery
  T1016     System Network Configuration Discovery
  T1070.004 Indicator Removal: File Deletion
  T1070.001 Indicator Removal: Clear Windows Event Logs
  T1135     Network Share Discovery
  T1046     Network Service Scanning
  T1087.002 Account Discovery: Domain Account
  T1125     Video Capture (webcam)
  T1123     Audio Capture (microphone)
  T1025     Data from Removable Media (USB)
  T1614.001 System Location Discovery
  T1055     Process Injection (recon only)
  T1087.003 Account Discovery: Email Account
  T1114.001 Email Collection: Local Email Collection

DEFENSIVE (D3FEND):
  D3-PM     Process Monitoring
  D3-NTA    Network Traffic Analysis
  D3-FH     File Hashing
  D3-FSB    File Content Signature-Based
  D3-MA     Memory Analysis
  D3-BAN    Behavioral Analysis


================================================================
  TROUBLESHOOTING
================================================================

"C2 server not reachable":
  - Check Kali VM is running
  - Verify IP: ping 192.168.56.101 from Windows
  - Make sure server.py is running on Kali
  - Check firewall: sudo ufw allow 4444 (on Kali)

"Cannot open camera":
  - Webcam may be in use by another app
  - Set COLLECT_WEBCAM = False in config.py to skip

"sounddevice not found":
  - pip install sounddevice numpy
  - Or set COLLECT_MICROPHONE = False in config.py

"schtasks access denied":
  - This is normal on some locked-down machines
  - Set ENABLE_SCHEDULED_TASK = False in config.py

Dashboard not loading:
  - Open http://KALI_IP:4444 in browser
  - Make sure flask is installed on Kali

SCP not working:
  - On Kali: sudo systemctl start ssh
  - Or use shared folder / USB to transfer files


================================================================
  CONFIG TOGGLES (config.py)
================================================================

Every feature can be independently enabled/disabled:

  COLLECT_SYSTEM_INFO = True/False
  COLLECT_FILES = True/False
  COLLECT_SCREENSHOTS = True/False
  COLLECT_KEYSTROKES = True/False
  COLLECT_CLIPBOARD = True/False
  COLLECT_BROWSER_DATA = True/False
  COLLECT_PRIVILEGE_INFO = True/False
  COLLECT_WIFI_PASSWORDS = True/False
  COLLECT_TOKENS = True/False
  COLLECT_NETWORK_RECON = True/False
  COLLECT_LATERAL_RECON = True/False
  COLLECT_EVENT_LOG_INFO = True/False
  COLLECT_WEBCAM = True/False
  COLLECT_MICROPHONE = True/False
  COLLECT_USB_DATA = True/False
  COLLECT_GEOLOCATION = True/False
  COLLECT_INJECTION_RECON = True/False
  COLLECT_EMAIL_DATA = True/False
  ENABLE_PERSISTENCE = True/False
  ENABLE_SCHEDULED_TASK = True/False
  ENABLE_STARTUP_FOLDER = True/False
  ENABLE_REMOTE_CMD = True/False
  ENCRYPT_COMMS = True/False
  STEALTH_MODE = True/False
  BEACON_JITTER = True/False
  ANTI_FORENSICS = True/False

================================================================
  END OF DEPLOYMENT GUIDE
================================================================
