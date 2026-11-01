"""
Authenticated Encryption for C2 Communications
MITRE ATT&CK: T1573.001 (Encrypted Channel: Symmetric Cryptography)
EDUCATIONAL PURPOSE ONLY - RMIT Cybersecurity Assignment

Hardened version of the original AES-CBC module:

Changes (defensive improvements):
  1. AES-256-CBC  -> AES-256-GCM (authenticated encryption; no padding oracle,
     no malleability).
  2. SHA-256 KDF  -> PBKDF2-HMAC-SHA256 with a per-key random salt and high
     iteration count (offline brute-force is far more expensive).
  3. Every ciphertext is tied to a random salt + nonce, so the same passphrase
     produces different ciphertexts each call (no static derived key reuse).

Payload format (base64):
    b64( SALT[16] || NONCE[12] || CIPHERTEXT || TAG[16] )

Backward compatibility: the old encrypt/decrypt functions kept the same
signature (encrypt_payload(dict, key) / decrypt_payload(str, key)) so the rest
of the codebase still works, but now "key" is the *passphrase* and the KDF is
performed inside. A new derive_key(passphrase, salt) helper is also exposed.
"""

import json
import base64
import os

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

SALT_SIZE = 16
NONCE_SIZE = 12  # GCM standard nonce length
TAG_SIZE = 16
KEY_SIZE = 32    # AES-256
PBKDF2_ITERATIONS = 600_000  # OWASP-recommended order of magnitude for HMAC-SHA256


def derive_key(passphrase, salt=None):
    """
    Derive a 32-byte AES-256 key from a passphrase using PBKDF2-HMAC-SHA256.

    Args:
        passphrase: str - shared secret.
        salt: bytes - optional 16-byte salt. If None, a new random salt is
              generated and returned alongside the key.

    Returns:
        (key, salt) tuple: key is 32 bytes, salt is 16 bytes.
    """
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")

    if salt is None:
        salt = os.urandom(SALT_SIZE)

    key = PBKDF2(passphrase, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS,
                 hmac_hash_module=SHA256)
    return key, salt


def encrypt_payload(data_dict, passphrase):
    """
    Encrypt a dict into a base64 string using AES-256-GCM.

    Format: b64( SALT[16] || NONCE[12] || CIPHERTEXT || TAG[16] )

    Args:
        data_dict: dict to encrypt.
        passphrase: str - shared secret (KDF is applied here).

    Returns:
        base64 string.
    """
    if isinstance(passphrase, bytes):
        passphrase = passphrase.decode("utf-8", errors="ignore")

    key, salt = derive_key(passphrase)
    nonce = os.urandom(NONCE_SIZE)

    plaintext = json.dumps(data_dict, default=str).encode("utf-8")

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return base64.b64encode(salt + nonce + ciphertext + tag).decode("utf-8")


def decrypt_payload(b64_data, passphrase):
    """
    Decrypt a base64 string produced by encrypt_payload().

    Raises ValueError on authentication failure (wrong key or tampered data).

    Args:
        b64_data: base64 string.
        passphrase: str - shared secret.

    Returns:
        dict.
    """
    if isinstance(passphrase, bytes):
        passphrase = passphrase.decode("utf-8", errors="ignore")

    raw = base64.b64decode(b64_data)

    salt = raw[:SALT_SIZE]
    nonce = raw[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    tag = raw[-TAG_SIZE:]
    ciphertext = raw[SALT_SIZE + NONCE_SIZE:-TAG_SIZE]

    key, _ = derive_key(passphrase, salt=salt)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # Tag verification is implicit in decrypt_and_verify(); a wrong tag raises.
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return json.loads(plaintext.decode("utf-8"))


if __name__ == "__main__":
    print("=" * 50)
    print("  AES-256-GCM (Authenticated) Encryption Test")
    print("=" * 50)

    test_passphrase = "rmit-edu-demo-2026"
    test_data = {
        "rat_id": "edu_rat_rmit",
        "data": {
            "hostname": "DESKTOP-TEST",
            "username": "student",
            "secret_info": "This should be authenticated & encrypted"
        }
    }

    print(f"\n[*] Passphrase: {test_passphrase}")
    print(f"[*] Original data: {json.dumps(test_data, indent=2)}")

    # 1. Round-trip
    enc1 = encrypt_payload(test_data, test_passphrase)
    enc2 = encrypt_payload(test_data, test_passphrase)
    print(f"\n[*] Encrypted #1: {enc1[:60]}...")
    print(f"[*] Encrypted #2: {enc2[:60]}...")
    print(f"[*] Ciphertexts differ (random salt/nonce)? {enc1 != enc2}")

    dec = decrypt_payload(enc1, test_passphrase)
    assert dec == test_data, "DECRYPTION MISMATCH!"
    print("[+] Round-trip PASSED")

    # 2. Wrong key must fail (authentication check)
    try:
        decrypt_payload(enc1, "wrong-passphrase")
        print("[-] FAIL: wrong key was accepted!")
    except (ValueError, KeyError, json.JSONDecodeError):
        print("[+] Authentication PASSED: wrong key rejected")

    # 3. Tampered ciphertext must fail
    tampered = bytearray(base64.b64decode(enc1))
    tampered[-1] ^= 0xFF  # flip a bit in the tag
    try:
        decrypt_payload(base64.b64encode(bytes(tampered)).decode(), test_passphrase)
        print("[-] FAIL: tampered data was accepted!")
    except (ValueError, KeyError, json.JSONDecodeError):
        print("[+] Authentication PASSED: tampering detected")

    print("\n[+] All tests complete.")
