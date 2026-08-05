"""
Lateral Movement Reconnaissance Module
MITRE ATT&CK: T1135 (Network Share Discovery)
                T1087.002 (Account Discovery: Domain Account)
                T1046 (Network Service Scanning)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Maps potential lateral movement paths from the compromised host:
  1. Remote share enumeration — what shares are accessible on each host
  2. Port scanning — find open RDP/SMB/SSH/WinRM on LAN hosts
  3. Domain info — discover domain name, controllers, trust relationships
  4. Admin share check — test if C$/ADMIN$ are accessible (admin indicator)
  5. Session enumeration — who else is logged into this machine

Real-world usage: After initial compromise, APTs use this to plan
lateral movement. Knowing which shares are writable and which hosts
have RDP open is the difference between a single-host compromise
and full domain takeover.
"""

import subprocess
import socket
import os
import re
import concurrent.futures


def scan_port(ip, port, timeout=1):
    """
    Check if a single port is open on a remote host.
    Uses a raw TCP connect with a short timeout.

    Returns:
        dict with ip, port, open bool, service hint
    """
    service_map = {
        21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP",
        135: "RPC", 139: "NetBIOS", 443: "HTTPS", 445: "SMB",
        1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM",
        5986: "WinRM-S", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return {
            "ip": ip,
            "port": port,
            "open": result == 0,
            "service": service_map.get(port, ""),
        }
    except Exception:
        return {"ip": ip, "port": port, "open": False, "service": ""}


def scan_host_ports(ip, ports=None, timeout=1):
    """
    Scan multiple ports on a single host using thread pool.
    Only returns open ports.

    Args:
        ip: Target IP address
        ports: List of ports to scan (default: common lateral movement ports)
        timeout: Socket connect timeout in seconds

    Returns:
        list of dicts for open ports: [{ip, port, service}]
    """
    if ports is None:
        ports = [22, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 5900, 5985]

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result["open"]:
                open_ports.append({
                    "ip": result["ip"],
                    "port": result["port"],
                    "service": result["service"],
                })

    return sorted(open_ports, key=lambda x: x["port"])


def scan_network_hosts(hosts, ports=None, timeout=1):
    """
    Scan multiple hosts for open ports.

    Args:
        hosts: List of IP addresses to scan
        ports: Ports to check per host
        timeout: Socket timeout

    Returns:
        dict keyed by IP: {ip: [{port, service}]}
    """
    results = {}
    # Limit to first 20 hosts to avoid scanning forever
    for ip in hosts[:20]:
        open_ports = scan_host_ports(ip, ports, timeout)
        if open_ports:
            results[ip] = open_ports
    return results


def enumerate_remote_shares(ip):
    """
    Enumerate SMB shares on a remote host using 'net view'.

    This reveals accessible file shares, which are potential
    data exfiltration targets or lateral movement paths.

    Args:
        ip: Target IP address

    Returns:
        list of dicts: [{name, type, remark}]
    """
    shares = []
    try:
        result = subprocess.run(
            ["net", "view", f"\\\\{ip}"],
            capture_output=True, text=True, timeout=10
        )

        if result.returncode == 0:
            lines = result.stdout.strip().split("\n")
            # Skip header lines and footer
            for line in lines:
                line = line.strip()
                if not line or "Share name" in line or "---" in line or "command completed" in line.lower():
                    continue
                if "\\\\".lower() in line.lower():
                    continue

                parts = line.split()
                if len(parts) >= 2:
                    share_name = parts[0]
                    share_type = parts[1] if len(parts) > 1 else ""
                    remark = " ".join(parts[2:]) if len(parts) > 2 else ""
                    shares.append({
                        "name": share_name,
                        "type": share_type,
                        "remark": remark,
                    })

    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    return shares


def check_admin_shares(ip):
    """
    Test if administrative shares (C$, ADMIN$, IPC$) are accessible.

    Admin share access = we have admin privileges on that remote host.
    This is the holy grail for lateral movement.

    Args:
        ip: Target IP address

    Returns:
        list of dicts: [{share, accessible, detail}]
    """
    admin_shares = ["C$", "ADMIN$", "IPC$"]
    results = []

    for share in admin_shares:
        unc_path = f"\\\\{ip}\\{share}"
        try:
            result = subprocess.run(
                ["net", "use", unc_path],
                capture_output=True, text=True, timeout=10
            )
            accessible = result.returncode == 0

            # Clean up the connection
            if accessible:
                subprocess.run(
                    ["net", "use", unc_path, "/delete", "/y"],
                    capture_output=True, text=True, timeout=5
                )

            results.append({
                "share": share,
                "path": unc_path,
                "accessible": accessible,
                "detail": "ADMIN ACCESS" if accessible else "access denied",
            })
        except Exception:
            results.append({
                "share": share,
                "path": unc_path,
                "accessible": False,
                "detail": "timeout/error",
            })

    return results


def get_domain_info():
    """
    Discover domain membership and domain controllers.

    Domain info reveals:
      - Domain name (target for Kerberoasting, AS-REP roasting)
      - Domain controllers (high-value targets)
      - Trust relationships (paths to other domains)

    Returns:
        dict with domain details
    """
    info = {
        "in_domain": False,
        "domain_name": None,
        "computer_name": None,
        "domain_controllers": [],
        "logon_server": None,
    }

    # Check domain membership
    try:
        result = subprocess.run(
            ["wmic", "computersystem", "get", "domain,partofdomain"],
            capture_output=True, text=True, timeout=10
        )
        lines = [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]
        if len(lines) >= 2:
            parts = lines[-1].split()
            if len(parts) >= 2:
                info["domain_name"] = parts[0]
                info["in_domain"] = parts[1].upper() == "TRUE"
    except Exception:
        pass

    # Get logon server
    info["logon_server"] = os.environ.get("LOGONSERVER", "").strip("\\")
    info["computer_name"] = os.environ.get("COMPUTERNAME", "")

    # Find domain controllers via nltest
    if info["in_domain"]:
        try:
            result = subprocess.run(
                ["nltest", "/dclist:" + (info["domain_name"] or "")],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line and "\\\\".lower() != line[:2].lower() and "." in line:
                    # Extract DC name
                    dc_name = line.split()[0].strip("\\").strip()
                    if dc_name and dc_name != "The":
                        info["domain_controllers"].append(dc_name)
        except Exception:
            pass

    # Domain users (limited, non-admin)
    return info


def get_logged_on_users():
    """
    Enumerate users with active sessions on this machine.

    Reveals:
      - Local interactive sessions
      - RDP sessions
      - Service accounts with tokens (token impersonation targets)

    Returns:
        list of dicts: [{username, session_name, session_id, state}]
    """
    users = []
    try:
        result = subprocess.run(
            ["query", "user"],
            capture_output=True, text=True, timeout=10
        )

        for line in result.stdout.strip().split("\n")[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 4:
                users.append({
                    "username": parts[0].lstrip(">"),
                    "session_name": parts[1] if len(parts) > 1 else "",
                    "session_id": parts[2] if len(parts) > 2 else "",
                    "state": parts[3] if len(parts) > 3 else "",
                })

    except Exception:
        pass

    return users


def get_domain_users():
    """
    Enumerate domain users if joined to a domain (T1087.002).
    Uses 'net user /domain' — limited output, doesn't need admin.

    Returns:
        list of usernames
    """
    users = []
    try:
        result = subprocess.run(
            ["net", "user", "/domain"],
            capture_output=True, text=True, timeout=15
        )

        if result.returncode == 0:
            # Parse the multi-column output
            in_users = False
            for line in result.stdout.split("\n"):
                if "---" in line:
                    in_users = True
                    continue
                if "command completed" in line.lower():
                    break
                if in_users and line.strip():
                    # Users are listed in columns
                    for name in line.split():
                        name = name.strip()
                        if name and not name.startswith("The"):
                            users.append(name)

    except Exception:
        pass

    return users


def full_lateral_recon(arp_hosts=None):
    """
    Run full lateral movement reconnaissance.

    Args:
        arp_hosts: List of IPs from ARP table (from network_recon).
                   If None, discovers hosts from ARP table.

    Returns:
        dict with all lateral movement intelligence
    """
    # Get hosts from ARP if not provided
    if arp_hosts is None:
        arp_hosts = []
        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split("\n"):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ip = match.group(1)
                    # Skip broadcast and multicast
                    if not ip.startswith("224.") and not ip.endswith(".255"):
                        arp_hosts.append(ip)
        except Exception:
            pass

    # 1. Port scan discovered hosts
    port_scan = scan_network_hosts(arp_hosts)

    # 2. Enumerate shares on hosts with SMB open
    smb_hosts = [ip for ip, ports in port_scan.items()
                 if any(p["port"] == 445 for p in ports)]
    remote_shares = {}
    for ip in smb_hosts[:10]:  # Limit to 10 hosts
        shares = enumerate_remote_shares(ip)
        if shares:
            remote_shares[ip] = shares

    # 3. Check admin shares on SMB hosts
    admin_access = {}
    for ip in smb_hosts[:5]:  # Limit to 5 hosts (slow operation)
        admin = check_admin_shares(ip)
        if any(a["accessible"] for a in admin):
            admin_access[ip] = admin

    # 4. Domain info
    domain = get_domain_info()

    # 5. Logged-on users
    sessions = get_logged_on_users()

    # 6. Domain users (if in domain)
    domain_users = []
    if domain.get("in_domain"):
        domain_users = get_domain_users()

    return {
        "port_scan": port_scan,
        "remote_shares": remote_shares,
        "admin_share_access": admin_access,
        "domain_info": domain,
        "logged_on_users": sessions,
        "domain_users": domain_users[:50],  # Cap at 50
        "summary": {
            "hosts_scanned": len(arp_hosts),
            "hosts_with_open_ports": len(port_scan),
            "smb_hosts": len(smb_hosts),
            "hosts_with_shares": len(remote_shares),
            "admin_access_hosts": len(admin_access),
            "in_domain": domain.get("in_domain", False),
            "domain_name": domain.get("domain_name"),
            "logged_on_users": len(sessions),
            "domain_users_found": len(domain_users),
        }
    }


if __name__ == "__main__":
    print("=" * 50)
    print("  Lateral Movement Reconnaissance Test")
    print("  T1135 + T1087.002 + T1046")
    print("=" * 50)

    # Domain info
    domain = get_domain_info()
    print(f"\n[{'+'if domain['in_domain'] else '-'}] Domain: {domain.get('domain_name', 'N/A')}")
    print(f"    In domain: {domain['in_domain']}")
    print(f"    Logon server: {domain.get('logon_server', 'N/A')}")
    if domain["domain_controllers"]:
        print(f"    Domain controllers: {', '.join(domain['domain_controllers'])}")

    # Logged on users
    sessions = get_logged_on_users()
    print(f"\n[{'+'if sessions else '-'}] Logged-on users: {len(sessions)}")
    for s in sessions:
        print(f"    {s['username']} ({s.get('session_name', '')}) - {s.get('state', '')}")

    # Discover hosts via ARP
    print("\n[*] Discovering hosts via ARP table...")
    hosts = []
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
        for line in result.stdout.split("\n"):
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)
                if not ip.startswith("224.") and not ip.endswith(".255"):
                    hosts.append(ip)
    except Exception:
        pass

    print(f"    Found {len(hosts)} hosts")

    # Port scan
    if hosts:
        print(f"\n[*] Scanning ports on {min(len(hosts), 10)} hosts...")
        results = scan_network_hosts(hosts[:10])
        for ip, ports in results.items():
            port_str = ", ".join(f"{p['port']}/{p['service']}" for p in ports)
            print(f"    {ip}: {port_str}")

        # Share enumeration
        smb_hosts = [ip for ip, ports in results.items()
                     if any(p["port"] == 445 for p in ports)]
        if smb_hosts:
            print(f"\n[*] Enumerating shares on {len(smb_hosts)} SMB hosts...")
            for ip in smb_hosts[:5]:
                shares = enumerate_remote_shares(ip)
                if shares:
                    print(f"    {ip}: {', '.join(s['name'] for s in shares)}")
                else:
                    print(f"    {ip}: (no shares visible)")
    else:
        print("\n[-] No hosts discovered for scanning")
