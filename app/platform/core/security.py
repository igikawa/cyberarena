import hashlib
import hmac
import secrets

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


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)
