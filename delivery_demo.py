"""
Delivery Mechanism Demo - EDUCATIONAL PURPOSE ONLY
Shows HOW an attacker would package and deliver the RAT.

This script does NOT actually create a weaponized payload.
It demonstrates the CONCEPT for your presentation.

MITRE ATT&CK:
  T1566.001 - Phishing: Spearphishing Attachment
  T1204.002 - User Execution: Malicious File
  T1036.005 - Masquerading: Match Legitimate Name
"""

import os


def explain_delivery_methods():
    """Presentation-ready explanation of delivery methods."""

    methods = {
        "1. Phishing Email (Most Common - 91% of attacks)": {
            "how": [
                "Craft email impersonating trusted entity (university, bank, employer)",
                "Attach RAT disguised as legitimate file (invoice, security tool, resume)",
                "Use urgency/fear to make victim act without thinking",
                "Victim downloads and runs the attachment → RAT executes"
            ],
            "real_world": "APT29 (Cozy Bear) used COVID-19 themed phishing to deliver malware",
            "mitre": "T1566.001",
            "defense": [
                "Email filtering (SPF, DKIM, DMARC)",
                "User awareness training",
                "Sandboxing email attachments",
                "Block executable attachments at gateway"
            ]
        },

        "2. USB Drop Attack": {
            "how": [
                "Load RAT onto USB drives with enticing labels ('Salary_Data_2026')",
                "Drop USBs in target's parking lot, lobby, or common areas",
                "Curious employee plugs it in → autorun or user opens file → RAT executes",
                "Can also use BadUSB/Rubber Ducky for keystroke injection"
            ],
            "real_world": "Stuxnet (2010) - Spread to Iran's Natanz nuclear facility via USB",
            "mitre": "T1091 - Replication Through Removable Media",
            "defense": [
                "Disable USB autorun via Group Policy",
                "USB device whitelisting (only approved devices)",
                "Endpoint Detection and Response (EDR)",
                "Physical security awareness training"
            ]
        },

        "3. Trojanized Software (Supply Chain)": {
            "how": [
                "Take a legitimate popular application",
                "Inject RAT code into the installer",
                "Host on fake download site or compromise real update server",
                "User installs 'legitimate' software → RAT runs silently alongside"
            ],
            "real_world": "SolarWinds (2020) - Malware injected into Orion update, 18,000 orgs compromised",
            "mitre": "T1195.002 - Supply Chain Compromise: Software Supply Chain",
            "defense": [
                "Verify software checksums/signatures before installing",
                "Application whitelisting",
                "Monitor for unexpected outbound connections",
                "Use official sources only"
            ]
        },

        "4. Watering Hole Attack": {
            "how": [
                "Identify websites the target frequently visits",
                "Compromise that website with exploit code",
                "When target visits → browser exploit → RAT downloads silently",
                "No user interaction needed (drive-by download)"
            ],
            "real_world": "NotPetya (2017) - Compromised Ukrainian tax software website",
            "mitre": "T1189 - Drive-by Compromise",
            "defense": [
                "Keep browsers and plugins updated",
                "Web filtering and URL reputation",
                "Browser sandboxing",
                "Network segmentation"
            ]
        }
    }

    print("=" * 60)
    print("  MALWARE DELIVERY METHODS - EDUCATIONAL REFERENCE")
    print("=" * 60)

    for method_name, details in methods.items():
        print(f"\n{'─' * 60}")
        print(f"\n  {method_name}")
        print(f"  MITRE ATT&CK: {details['mitre']}")
        print(f"\n  How it works:")
        for step in details["how"]:
            print(f"    → {step}")
        print(f"\n  Real-world example: {details['real_world']}")
        print(f"\n  Defenses:")
        for d in details["defense"]:
            print(f"    ✓ {d}")

    # How OUR RAT would be delivered
    print(f"\n{'=' * 60}")
    print("  HOW OUR RAT WOULD BE DELIVERED")
    print(f"{'=' * 60}")
    print("""
  ATTACK SCENARIO: Targeting RMIT student

  Step 1: RECONNAISSANCE
    - Find target's email from RMIT directory
    - Identify what they study (cybersecurity → ironic)
    - Note: semester dates, exam periods (high stress = less careful)

  Step 2: WEAPONIZATION
    - Package rat_client.py as 'RMIT_Security_Check.exe'
    - Use PyInstaller to convert Python → single .exe
    - Command: pyinstaller --onefile --noconsole rat_client.py
    - Rename output to look legitimate

  Step 3: DELIVERY
    - Send phishing email (see phishing_email.html)
    - Subject: "Urgent: RMIT Account Security Review"
    - Attachment: RMIT_Security_Check.exe

  Step 4: EXPLOITATION
    - Victim downloads and runs the "security tool"
    - Windows might show SmartScreen warning
    - But urgency in email makes victim click "Run Anyway"

  Step 5: INSTALLATION
    - RAT connects to C2 server
    - Begins collecting system info, files, screenshots

  Step 6: COMMAND & CONTROL
    - Attacker monitors dashboard on C2 server
    - Receives all exfiltrated data
    - Can activate kill switch when done

  Step 7: ACTIONS ON OBJECTIVES
    - Steal credentials, documents, personal data
    - Maintain persistence for future access
""")


if __name__ == "__main__":
    explain_delivery_methods()
