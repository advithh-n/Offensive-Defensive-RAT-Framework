"""
Process Injection Concept Demo (READ-ONLY / EDUCATIONAL)
MITRE ATT&CK: T1055 (Process Injection)
               T1055.012 (Process Hollowing)
               T1055.001 (DLL Injection)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

IMPORTANT: This module does NOT perform actual injection.
It demonstrates the CONCEPTS and detects injection OPPORTUNITIES.
Actual injection would require shellcode and is beyond assignment scope.

Why process injection matters:
  - Runs malicious code inside a legitimate process (e.g., svchost.exe)
  - Inherits the trust level of the host process
  - Bypasses application whitelisting
  - Evades process-based detection (AV sees svchost, not malware)
  - Used by nearly every APT group (Lazarus, APT28, APT29)

What this module does:
  1. Enumerates injectable processes (candidates for injection)
  2. Checks which DLL injection techniques are available
  3. Demonstrates hollowing detection by analyzing process memory
  4. Reports findings for the assignment report
"""

import os
import sys
from datetime import datetime

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import ctypes
    from ctypes import wintypes
    HAS_CTYPES = True
except ImportError:
    HAS_CTYPES = False


# Ideal processes for injection (commonly targeted by real malware)
INJECTABLE_TARGETS = {
    "svchost.exe": "Service Host - most commonly targeted, many instances",
    "explorer.exe": "Windows Explorer - always running, user-level",
    "notepad.exe": "Notepad - simple process, easy to hollow",
    "RuntimeBroker.exe": "Runtime Broker - common UWP process",
    "dllhost.exe": "COM Surrogate - frequently spawned",
    "sihost.exe": "Shell Infrastructure Host - always running",
    "taskhostw.exe": "Task Host Window - runs scheduled tasks",
    "SearchHost.exe": "Windows Search - always running",
}


def enumerate_injectable_processes():
    """
    Find processes that would be suitable targets for injection.

    Criteria:
    - Running as current user (not SYSTEM, unless we're admin)
    - Known injectable targets
    - Has sufficient permissions to open

    Returns:
        list of candidate process dicts

    MITRE ATT&CK: T1055 (Process Injection - reconnaissance phase)
    """
    if not HAS_PSUTIL:
        return []

    candidates = []
    current_user = os.environ.get("USERNAME", "").lower()

    for proc in psutil.process_iter(["pid", "name", "username", "memory_info"]):
        try:
            info = proc.info
            name = (info["name"] or "").lower()

            if name in [k.lower() for k in INJECTABLE_TARGETS]:
                # Get the description for this target
                desc = INJECTABLE_TARGETS.get(info["name"], "")
                if not desc:
                    # Case-insensitive lookup
                    for k, v in INJECTABLE_TARGETS.items():
                        if k.lower() == name:
                            desc = v
                            break

                proc_user = (info["username"] or "").split("\\")[-1].lower()
                is_same_user = proc_user == current_user

                # Check if process is accessible
                accessible = False
                if HAS_CTYPES:
                    try:
                        PROCESS_QUERY_LIMITED = 0x1000
                        handle = ctypes.windll.kernel32.OpenProcess(
                            PROCESS_QUERY_LIMITED, False, info["pid"]
                        )
                        if handle:
                            accessible = True
                            ctypes.windll.kernel32.CloseHandle(handle)
                    except Exception:
                        pass

                mem_mb = 0
                if info["memory_info"]:
                    mem_mb = round(info["memory_info"].rss / (1024 * 1024), 1)

                candidates.append({
                    "pid": info["pid"],
                    "name": info["name"],
                    "user": info["username"],
                    "same_user": is_same_user,
                    "accessible": accessible,
                    "memory_mb": mem_mb,
                    "description": desc,
                    "injection_viable": is_same_user and accessible,
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return candidates


def check_injection_techniques():
    """
    Check which injection techniques are available on this system.

    This is a READ-ONLY check — it verifies API availability without
    actually performing injection.

    Returns:
        list of available technique dicts

    MITRE ATT&CK: T1055.001 (DLL Injection), T1055.012 (Process Hollowing)
    """
    techniques = []

    if not HAS_CTYPES:
        return [{"technique": "None", "available": False, "reason": "ctypes not available"}]

    # Check 1: VirtualAllocEx + WriteProcessMemory (Classic DLL Injection)
    try:
        kernel32 = ctypes.windll.kernel32
        has_virtual_alloc = hasattr(kernel32, 'VirtualAllocEx')
        has_write_mem = hasattr(kernel32, 'WriteProcessMemory')
        has_create_thread = hasattr(kernel32, 'CreateRemoteThread')

        techniques.append({
            "technique": "Classic DLL Injection (T1055.001)",
            "apis_needed": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
            "available": has_virtual_alloc and has_write_mem and has_create_thread,
            "description": "Allocate memory in target, write DLL path, create remote thread to load it",
        })
    except Exception:
        pass

    # Check 2: NtUnmapViewOfSection (Process Hollowing)
    try:
        ntdll = ctypes.windll.ntdll
        has_unmap = hasattr(ntdll, 'NtUnmapViewOfSection')

        techniques.append({
            "technique": "Process Hollowing (T1055.012)",
            "apis_needed": ["NtUnmapViewOfSection", "VirtualAllocEx", "WriteProcessMemory"],
            "available": has_unmap and has_virtual_alloc and has_write_mem,
            "description": "Create suspended process, hollow out memory, replace with malicious code",
        })
    except Exception:
        pass

    # Check 3: QueueUserAPC (APC Injection)
    try:
        has_apc = hasattr(kernel32, 'QueueUserAPC')

        techniques.append({
            "technique": "APC Injection (T1055.004)",
            "apis_needed": ["QueueUserAPC", "VirtualAllocEx", "WriteProcessMemory"],
            "available": has_apc and has_virtual_alloc and has_write_mem,
            "description": "Queue APC to target thread; executes when thread enters alertable state",
        })
    except Exception:
        pass

    # Check 4: SetWindowsHookEx (Hook Injection)
    try:
        user32 = ctypes.windll.user32
        has_hook = hasattr(user32, 'SetWindowsHookExW')

        techniques.append({
            "technique": "Hook Injection (T1055.012)",
            "apis_needed": ["SetWindowsHookExW"],
            "available": has_hook,
            "description": "Install global hook that forces target to load malicious DLL",
        })
    except Exception:
        pass

    return techniques


def detect_existing_injections():
    """
    Attempt to detect if any running processes show signs of injection.
    This is a DEFENSIVE check that could be used by the AV.

    Checks:
    - Processes with suspicious parent-child relationships
    - svchost.exe running without services.exe as parent
    - Processes with unusually high memory for their type

    Returns:
        list of suspicious findings
    """
    if not HAS_PSUTIL:
        return []

    findings = []

    for proc in psutil.process_iter(["pid", "name", "ppid", "memory_info"]):
        try:
            info = proc.info
            name = (info["name"] or "").lower()

            # Check 1: svchost.exe must have services.exe as parent
            if name == "svchost.exe":
                try:
                    parent = psutil.Process(info["ppid"])
                    if parent.name().lower() != "services.exe":
                        findings.append({
                            "type": "suspicious_parent",
                            "pid": info["pid"],
                            "name": info["name"],
                            "parent_pid": info["ppid"],
                            "parent_name": parent.name(),
                            "detail": f"svchost.exe (PID {info['pid']}) has unexpected parent: {parent.name()} (PID {info['ppid']})",
                            "severity": "HIGH",
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Check 2: Unusually high memory for lightweight processes
            if name in ["notepad.exe", "calc.exe"] and info["memory_info"]:
                mem_mb = info["memory_info"].rss / (1024 * 1024)
                if mem_mb > 100:  # Notepad shouldn't use >100MB
                    findings.append({
                        "type": "memory_anomaly",
                        "pid": info["pid"],
                        "name": info["name"],
                        "memory_mb": round(mem_mb, 1),
                        "detail": f"{info['name']} (PID {info['pid']}) using {mem_mb:.0f} MB (unusually high)",
                        "severity": "MEDIUM",
                    })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return findings


def full_injection_recon():
    """
    Complete process injection reconnaissance.

    Returns:
        dict with all injection-related findings
    """
    candidates = enumerate_injectable_processes()
    techniques = check_injection_techniques()
    existing = detect_existing_injections()

    viable = [c for c in candidates if c.get("injection_viable")]

    return {
        "timestamp": datetime.now().isoformat(),
        "injectable_processes": candidates,
        "available_techniques": techniques,
        "existing_injection_indicators": existing,
        "summary": {
            "total_targets_found": len(candidates),
            "viable_targets": len(viable),
            "techniques_available": sum(1 for t in techniques if t.get("available")),
            "existing_injection_signs": len(existing),
        },
    }


if __name__ == "__main__":
    print("=" * 55)
    print("  Process Injection Reconnaissance (READ-ONLY)")
    print("  MITRE ATT&CK: T1055")
    print("  NOTE: No actual injection performed")
    print("=" * 55)

    print("\n[*] Enumerating injectable processes...")
    candidates = enumerate_injectable_processes()
    viable = [c for c in candidates if c.get("injection_viable")]
    print(f"[+] Found {len(candidates)} targets ({len(viable)} viable)")
    for c in candidates[:10]:
        status = "VIABLE" if c["injection_viable"] else "blocked"
        print(f"    PID {c['pid']:6d} {c['name']:<25s} [{status}] {c['description']}")

    print("\n[*] Checking available techniques...")
    techniques = check_injection_techniques()
    for t in techniques:
        status = "AVAILABLE" if t["available"] else "N/A"
        print(f"    [{status}] {t['technique']}")
        print(f"            {t['description']}")

    print("\n[*] Checking for existing injections...")
    findings = detect_existing_injections()
    if findings:
        for f in findings:
            print(f"    [{f['severity']}] {f['detail']}")
    else:
        print("    No injection indicators found")
