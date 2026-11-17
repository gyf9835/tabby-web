"""Decrypt a Tabby encrypted config storage (vault).

Mirrors tabby-core/src/services/vault.service.ts:
  key  = PBKDF2-SHA512(passphrase, keySalt, 100000 iterations, 32 bytes)
  data = AES-256-CBC decrypt(base64(contents), key, base64(iv))  -> JSON
  decrypted JSON = {"config": {...}, "secrets": [{type, key, value}, ...]}
"""

import base64
import hashlib
import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

PBKDF_ITERATIONS = 100000
PBKDF_DIGEST = "sha512"
CRYPT_KEY_LENGTH = 32


def derive_key(passphrase: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        PBKDF_DIGEST, passphrase, salt, PBKDF_ITERATIONS, dklen=CRYPT_KEY_LENGTH
    )


def decrypt_stored_vault(stored: dict, passphrase: str) -> dict:
    """stored = {"version": 1, "contents": b64, "keySalt": b64, "iv": b64}"""
    key = derive_key(passphrase.encode("utf-8"), base64.b64decode(stored["keySalt"]))
    iv = base64.b64decode(stored["iv"])
    ciphertext = base64.b64decode(stored["contents"])

    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    return json.loads(plaintext.decode("utf-8"))


def is_encrypted_config(data: dict) -> bool:
    """The synced config.yaml with encryption enabled looks like:
    {"vault": {"version": .., "contents": .., "keySalt": .., "iv": ..},
     "encrypted": true, "configSync": {...}}"""
    if not isinstance(data, dict):
        return False
    vault = data.get("vault")
    if isinstance(vault, dict) and vault.get("contents") and vault.get("keySalt"):
        return True
    return bool(data.get("encrypted"))
