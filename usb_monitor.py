"""
USB / Removable Media Monitor
MITRE ATT&CK: T1025 (Data from Removable Media)
                T1052.001 (Exfiltration Over Physical Medium: USB)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Detects USB drives and removable media, then scans for interesting files.
This demonstrates how malware can spread via USB or steal data from removable drives.

Why this matters:
  - USB drives often contain sensitive documents, passwords, crypto wallets
  - Air-gapped networks can be bridged via USB (Stuxnet used this)
  - Users frequently plug in USB drives with company data
  - Autorun malware historically spread via USB

Implementation:
  - Uses win32api/ctypes to detect drive types
  - Monitors for new drive insertions
  - Scans removable drives for interesting files
"""

import os
import string
import time
from datetime import datetime

try:
    import ctypes
    HAS_CTYPES = True
except ImportError:
    HAS_CTYPES = False


# Windows drive types (from GetDriveType API)
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5

# Interesting file extensions to flag on USB drives
USB_INTERESTING_EXTENSIONS = [
    ".txt", ".pdf", ".docx", ".xlsx", ".csv", ".json",
    ".env", ".config", ".key", ".pem", ".pfx", ".p12",
    ".kdbx", ".wallet", ".dat", ".bak", ".sql",
    ".zip", ".7z", ".rar",
]

# Maximum file size to read (5 MB)
MAX_USB_FILE_SIZE = 5 * 1024 * 1024


def get_removable_drives():
    """
    Enumerate all removable drives (USB sticks, external HDDs).

    Uses Windows GetDriveType API to identify removable media.

    Returns:
        list of dicts with drive info
    """
    if not HAS_CTYPES:
        return []

    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()

    for i in range(26):
        if bitmask & (1 << i):
            letter = chr(ord('A') + i)
            drive_path = f"{letter}:\\"

            try:
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)

                if drive_type == DRIVE_REMOVABLE:
                    # Get volume info
                    vol_name_buf = ctypes.create_unicode_buffer(256)
                    fs_name_buf = ctypes.create_unicode_buffer(256)
                    serial = ctypes.c_uint32()

                    ctypes.windll.kernel32.GetVolumeInformationW(
                        drive_path,
                        vol_name_buf, 256,
                        ctypes.byref(serial),
                        None, None,
                        fs_name_buf, 256
                    )

                    # Get disk space
                    free_bytes = ctypes.c_ulonglong()
                    total_bytes = ctypes.c_ulonglong()
                    ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                        drive_path,
                        None,
                        ctypes.byref(total_bytes),
                        ctypes.byref(free_bytes)
                    )

                    drives.append({
                        "drive_letter": letter,
                        "path": drive_path,
                        "volume_name": vol_name_buf.value or "Unknown",
                        "filesystem": fs_name_buf.value or "Unknown",
                        "serial_number": hex(serial.value),
                        "total_gb": round(total_bytes.value / (1024**3), 2),
                        "free_gb": round(free_bytes.value / (1024**3), 2),
                    })
            except Exception:
                continue

    return drives


def scan_usb_drive(drive_path, max_depth=3):
    """
    Scan a USB drive for interesting files.

    Args:
        drive_path: Root path of the drive (e.g., "E:\\")
        max_depth: Maximum directory depth to scan

    Returns:
        dict with scan results
    """
    interesting_files = []
    total_files = 0
    total_dirs = 0

    def _scan(path, depth):
        nonlocal total_files, total_dirs

        if depth > max_depth:
            return

        try:
            entries = os.listdir(path)
        except PermissionError:
            return
        except Exception:
            return

        for entry in entries:
            full_path = os.path.join(path, entry)

            try:
                if os.path.isdir(full_path):
                    total_dirs += 1
                    # Skip system/hidden directories
                    if entry.startswith('.') or entry.startswith('$'):
                        continue
                    _scan(full_path, depth + 1)

                elif os.path.isfile(full_path):
                    total_files += 1
                    ext = os.path.splitext(entry)[1].lower()

                    if ext in USB_INTERESTING_EXTENSIONS:
                        size = os.path.getsize(full_path)
                        interesting_files.append({
                            "name": entry,
                            "path": full_path,
                            "extension": ext,
                            "size_bytes": size,
                            "modified": datetime.fromtimestamp(
                                os.path.getmtime(full_path)
                            ).isoformat(),
                        })
            except Exception:
                continue

    _scan(drive_path, 0)

    return {
        "drive_path": drive_path,
        "total_files": total_files,
        "total_dirs": total_dirs,
        "interesting_files": interesting_files,
        "interesting_count": len(interesting_files),
        "scan_time": datetime.now().isoformat(),
    }


def monitor_usb_insertions(callback=None, poll_interval=5, stop_event=None):
    """
    Continuously monitor for new USB drive insertions.

    Args:
        callback: Function to call when new drive detected (receives drive info)
        poll_interval: Seconds between checks
        stop_event: threading.Event to signal stop

    Yields:
        New drive info dicts as they are detected
    """
    known_drives = set()

    # Initial snapshot
    for d in get_removable_drives():
        known_drives.add(d["drive_letter"])

    while True:
        if stop_event and stop_event.is_set():
            break

        current_drives = get_removable_drives()
        current_letters = set(d["drive_letter"] for d in current_drives)

        # Check for new drives
        new_letters = current_letters - known_drives
        for d in current_drives:
            if d["drive_letter"] in new_letters:
                if callback:
                    callback(d)
                yield d

        # Check for removed drives
        removed = known_drives - current_letters
        for letter in removed:
            pass  # Drive removed - could log this

        known_drives = current_letters

        if stop_event:
            stop_event.wait(poll_interval)
        else:
            time.sleep(poll_interval)


def full_usb_recon():
    """
    One-time USB reconnaissance: enumerate drives + scan for files.

    Returns:
        dict with all USB drive data
    """
    drives = get_removable_drives()
    scan_results = []

    for drive in drives:
        scan = scan_usb_drive(drive["path"])
        scan_results.append({
            **drive,
            "scan": scan,
        })

    return {
        "timestamp": datetime.now().isoformat(),
        "removable_drives_found": len(drives),
        "drives": scan_results,
        "summary": {
            "drives_found": len(drives),
            "total_interesting_files": sum(
                s["scan"]["interesting_count"] for s in scan_results
            ),
        },
    }


if __name__ == "__main__":
    print("=" * 50)
    print("  USB / Removable Media Monitor Test")
    print("  MITRE ATT&CK: T1025")
    print("=" * 50)

    drives = get_removable_drives()
    print(f"\n[*] Removable drives found: {len(drives)}")

    for d in drives:
        print(f"\n  Drive {d['drive_letter']}:")
        print(f"    Volume: {d['volume_name']}")
        print(f"    Filesystem: {d['filesystem']}")
        print(f"    Size: {d['total_gb']} GB (Free: {d['free_gb']} GB)")
        print(f"    Serial: {d['serial_number']}")

        scan = scan_usb_drive(d["path"])
        print(f"    Files: {scan['total_files']} total, {scan['interesting_count']} interesting")
        for f in scan["interesting_files"][:10]:
            print(f"      {f['name']} ({f['size_bytes']} bytes)")

    if not drives:
        print("  No removable drives detected")
