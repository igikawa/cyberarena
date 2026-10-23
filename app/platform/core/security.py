import hashlib
import hmac
import secrets
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pwdlib import PasswordHash

from app.platform.core.config import get_settings

password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return password_hash.verify(password, hashed)
    except (ValueError, TypeError):
        return False


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def hash_session_token(token: str) -> str:
    key = get_settings().secret_key.encode()
    return hmac.new(key, token.encode(), hashlib.sha256).hexdigest()


def hash_flag(flag: str) -> str:
    key = get_settings().flag_hmac_key.encode()
    return hmac.new(key, flag.encode(), hashlib.sha256).hexdigest()


def verify_flag(flag: str, expected: str) -> bool:
    return hmac.compare_digest(hash_flag(flag), expected)


def encrypt_flag(flag: str) -> str:
    key = hashlib.sha256(b"cyberarena/flag-encryption/v1\0" + get_settings().secret_key.encode()).digest()
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, flag.encode(), None)
    return "v1:" + base64.urlsafe_b64encode(nonce + ciphertext).decode()


def decrypt_flag(encrypted_flag: str) -> str:
    version, separator, encoded = encrypted_flag.partition(":")
    if version != "v1" or not separator:
        raise ValueError("Unsupported encrypted flag format")
    payload = base64.b64decode(encoded, altchars=b"-_", validate=True)
    nonce, ciphertext = payload[:12], payload[12:]
    if len(nonce) != 12 or not ciphertext:
        raise ValueError("Invalid encrypted flag payload")
    key = hashlib.sha256(b"cyberarena/flag-encryption/v1\0" + get_settings().secret_key.encode()).digest()
    return AESGCM(key).decrypt(nonce, ciphertext, None).decode()


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)
