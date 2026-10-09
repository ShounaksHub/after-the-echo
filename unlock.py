#!/usr/bin/env python3
"""SPECTRONA: After the Echo - archive decryptor.

Place archive.enc next to this script, install requirements.txt, and run:
    python unlock.py
The script asks for the passphrase derived from the clue.
"""
from __future__ import annotations

import base64
import getpass
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Missing dependency. Install it with: python -m pip install -r requirements.txt")
    sys.exit(2)

ARCHIVE_PATH = Path(__file__).with_name("archive.enc")
MAGIC = "SPECTRONA-AFTER-THE-ECHO-V1"
PBKDF2_ITERATIONS = 300_000


def derive_key(passphrase: str, salt: bytes) -> bytes:
    if not passphrase:
        raise ValueError("Passphrase cannot be empty.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def main() -> int:
    if not ARCHIVE_PATH.is_file():
        print(f"Archive not found: {ARCHIVE_PATH}")
        print("Place archive.enc in the same folder as unlock.py.")
        return 2

    try:
        envelope = json.loads(ARCHIVE_PATH.read_text(encoding="utf-8"))
        if envelope.get("format") != MAGIC:
            raise ValueError("Unrecognized archive format.")
        salt = base64.b64decode(envelope["salt"], validate=True)
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        if len(salt) != 16 or len(nonce) != 12 or len(ciphertext) < 16:
            raise ValueError("Archive fields have invalid lengths.")
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(f"Could not read archive: {exc}")
        return 2

    passphrase = getpass.getpass("Passphrase: ")
    try:
        key = derive_key(passphrase, salt)
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, MAGIC.encode("ascii"))
        message = plaintext.decode("utf-8").strip()
    except Exception:
        print("Decryption failed. Check the passphrase and the archive file.")
        return 1

    # The plaintext is expected to be a URL. Do not open it automatically.
    parsed = urlparse(message)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        print("Archive decrypted, but its contents are not a valid HTTP(S) URL:")
        print(message)
        return 0

    print("Archive decrypted successfully.")
    print("Next destination:")
    print(message)
    print("Open the URL manually in your browser.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
