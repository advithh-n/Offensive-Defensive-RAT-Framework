"""
Privilege Reconnaissance Module
MITRE ATT&CK: T1033 (System Owner/User Discovery)
               T1548.002 (Abuse Elevation Control: Bypass UAC) — awareness only
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Gathers privilege information: admin status, UAC settings, group memberships,
and identifies potential privilege escalation paths.
READ-ONLY RECON — does NOT attempt any escalation.
"""

import ctypes
import os
import subprocess
import winreg


def is_admin():
    """
    Check if the current process is running with admin privileges.
    Uses Windows API IsUserAnAdmin().

    Returns:
        True if running as admin, False otherwise
    """
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def get_privilege_info():
    """
    Gather current user privilege information.

    Returns:
        dict with username, admin status, groups, integrity level
    """
    info = {
        "username": os.environ.get("USERNAME", "unknown"),
        "userdomain": os.environ.get("USERDOMAIN", "unknown"),
        "is_admin": is_admin(),
        "groups": [],
        "integrity_level": "unknown"
    }

    # Get group memberships and integrity level via whoami /groups (single call)
    try:
        result = subprocess.run(
            ["whoami", "/groups"],
            capture_output=True, text=True, timeout=10
        )
        if result.stdout:
            lines = result.stdout.strip().split("\n")
            for line in lines:
                line = line.strip()
                # Skip header lines
                if not line or "GROUP" in line.upper() and "TYPE" in line.upper():
                    continue
                if "===" in line:
                    continue
                # Extract group name (first column)
                parts = line.split()
                if len(parts) >= 1 and "\\" in parts[0]:
                    info["groups"].append(parts[0])

            # Parse integrity level from the same output
            output = result.stdout.lower()
            if "high mandatory level" in output:
                info["integrity_level"] = "High (Admin)"
            elif "medium mandatory level" in output:
                info["integrity_level"] = "Medium (Standard User)"
            elif "low mandatory level" in output:
                info["integrity_level"] = "Low (Restricted)"
            elif "system mandatory level" in output:
                info["integrity_level"] = "System"
    except Exception:
        pass

    return info


def check_uac_settings():
    """
    Read UAC (User Account Control) configuration from registry.
    Path: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System

    Returns:
        dict with UAC settings and risk assessment
    """
    uac_info = {
        "EnableLUA": None,
        "ConsentPromptBehaviorAdmin": None,
        "PromptOnSecureDesktop": None,
        "uac_enabled": False,
        "uac_level": "unknown",
        "risk_assessment": ""
    }

    reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_READ)

        try:
            uac_info["EnableLUA"], _ = winreg.QueryValueEx(key, "EnableLUA")
        except FileNotFoundError:
            pass

        try:
            uac_info["ConsentPromptBehaviorAdmin"], _ = winreg.QueryValueEx(
                key, "ConsentPromptBehaviorAdmin"
            )
        except FileNotFoundError:
            pass

        try:
            uac_info["PromptOnSecureDesktop"], _ = winreg.QueryValueEx(
                key, "PromptOnSecureDesktop"
            )
        except FileNotFoundError:
            pass

        winreg.CloseKey(key)
    except Exception:
        uac_info["risk_assessment"] = "Cannot read UAC settings (access denied)"
        return uac_info

    # Interpret settings
    uac_info["uac_enabled"] = uac_info["EnableLUA"] == 1

    consent = uac_info["ConsentPromptBehaviorAdmin"]
    secure = uac_info["PromptOnSecureDesktop"]

    if consent == 0:
        uac_info["uac_level"] = "Never notify (DISABLED)"
        uac_info["risk_assessment"] = "HIGH RISK - UAC effectively disabled"
    elif consent == 5 and secure == 0:
        uac_info["uac_level"] = "Notify without secure desktop"
        uac_info["risk_assessment"] = "MEDIUM RISK - vulnerable to UI spoofing"
    elif consent == 5 and secure == 1:
        uac_info["uac_level"] = "Default - notify for app changes"
        uac_info["risk_assessment"] = "LOW RISK - standard configuration"
    elif consent == 2:
        uac_info["uac_level"] = "Always notify (maximum)"
        uac_info["risk_assessment"] = "MINIMAL RISK - highest UAC level"
    else:
        uac_info["uac_level"] = f"Custom (consent={consent}, secure={secure})"
        uac_info["risk_assessment"] = "Custom configuration - review manually"

    return uac_info


def find_escalation_opportunities():
    """
    Identify potential privilege escalation paths (READ-ONLY).
    Does NOT attempt any escalation — just reports what it finds.

    Checks:
    1. Unquoted service paths (wmic)
    2. Writable Program Files directories
    3. AlwaysInstallElevated registry key
    4. SYSTEM scheduled tasks with writable paths
    """
    opportunities = []

    # 1. Unquoted service paths
    try:
        result = subprocess.run(
            ["wmic", "service", "get", "name,displayname,pathname,startmode"],
            capture_output=True, text=True, timeout=15
        )
        for line in result.stdout.split("\n"):
            line = line.strip()
            if not line or "PathName" in line:
                continue
            # Look for paths with spaces that aren't quoted
            if "program files" in line.lower() and '"' not in line:
                parts = line.split()
                if len(parts) >= 2:
                    opportunities.append({
                        "type": "unquoted_service_path",
                        "detail": line[:200],
                        "risk": "HIGH",
                        "technique": "T1574.009"
                    })
    except Exception:
        pass

    # 2. Writable Program Files directories
    program_dirs = [
        os.environ.get("PROGRAMFILES", r"C:\Program Files"),
        os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
    ]
    for pdir in program_dirs:
        if not os.path.exists(pdir):
            continue
        try:
            for entry in os.listdir(pdir):
                full_path = os.path.join(pdir, entry)
                if os.path.isdir(full_path) and os.access(full_path, os.W_OK):
                    opportunities.append({
                        "type": "writable_program_dir",
                        "detail": full_path,
                        "risk": "MEDIUM",
                        "technique": "T1574.010"
                    })
        except PermissionError:
            continue

    # 3. AlwaysInstallElevated check
    for hive, hive_name in [(winreg.HKEY_CURRENT_USER, "HKCU"),
                             (winreg.HKEY_LOCAL_MACHINE, "HKLM")]:
        try:
            key = winreg.OpenKey(
                hive,
                r"SOFTWARE\Policies\Microsoft\Windows\Installer",
                0, winreg.KEY_READ
            )
            value, _ = winreg.QueryValueEx(key, "AlwaysInstallElevated")
            winreg.CloseKey(key)
            if value == 1:
                opportunities.append({
                    "type": "always_install_elevated",
                    "detail": f"{hive_name}\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer = 1",
                    "risk": "CRITICAL",
                    "technique": "T1548.002"
                })
        except (FileNotFoundError, PermissionError, OSError):
            continue

    # 4. SYSTEM scheduled tasks with writable paths
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            capture_output=True, text=True, timeout=15
        )
        for line in result.stdout.split("\n"):
            if "SYSTEM" in line:
                parts = line.split(",")
                for part in parts:
                    part = part.strip('"')
                    if os.path.exists(part) and os.access(part, os.W_OK):
                        opportunities.append({
                            "type": "writable_system_task",
                            "detail": f"SYSTEM task path writable: {part}",
                            "risk": "HIGH",
                            "technique": "T1053.005"
                        })
    except Exception:
        pass

    return opportunities


if __name__ == "__main__":
    print("=" * 50)
    print("  Privilege Reconnaissance")
    print("=" * 50)

    # Admin check
    admin = is_admin()
    print(f"\n[*] Running as admin: {'YES' if admin else 'NO'}")

    # Privilege info
    priv_info = get_privilege_info()
    print(f"[*] Username: {priv_info['userdomain']}\\{priv_info['username']}")
    print(f"[*] Integrity level: {priv_info['integrity_level']}")
    print(f"[*] Group memberships: {len(priv_info['groups'])}")
    for g in priv_info["groups"][:10]:
        print(f"    {g}")

    # UAC settings
    uac = check_uac_settings()
    print(f"\n[*] UAC Settings:")
    print(f"    Enabled: {uac['uac_enabled']}")
    print(f"    Level: {uac['uac_level']}")
    print(f"    Risk: {uac['risk_assessment']}")

    # Escalation opportunities
    print(f"\n[*] Scanning for escalation opportunities...")
    opps = find_escalation_opportunities()
    if opps:
        print(f"[!] Found {len(opps)} potential escalation path(s):")
        for o in opps:
            print(f"    [{o['risk']}] {o['type']}: {o['detail'][:100]}")
    else:
        print(f"[+] No obvious escalation paths found")
