import os
import re
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class Settings:
    database_url: str
    secret_key: str
    flag_hmac_key: str
    lab_flags_file: Path
    admin_username: str | None
    admin_password: str | None
    secure_cookies: bool
    session_ttl_hours: int
    templates_dir: Path
    static_dir: Path


def get_settings() -> Settings:
    database_url = os.getenv("DATABASE_URL", "")
    secret_key = os.getenv("SECRET_KEY", "")
    flag_hmac_key = os.getenv("FLAG_HMAC_KEY", "")
    if not database_url:
        raise RuntimeError("DATABASE_URL must be configured")
    if len(secret_key) < 32 or len(flag_hmac_key) < 32:
        raise RuntimeError("SECRET_KEY and FLAG_HMAC_KEY must each contain at least 32 characters")
    if secret_key == flag_hmac_key:
        raise RuntimeError("SECRET_KEY and FLAG_HMAC_KEY must be different")
    admin_username = os.getenv("ADMIN_USERNAME") or None
    admin_password = os.getenv("ADMIN_PASSWORD") or None
    if not admin_username or not re.fullmatch(r"[A-Za-z0-9_]{3,32}", admin_username):
        raise RuntimeError("ADMIN_USERNAME must contain 3-32 ASCII letters, digits, or underscores")
    if not admin_password or not 12 <= len(admin_password) <= 128:
        raise RuntimeError("ADMIN_PASSWORD must contain between 12 and 128 characters")
    session_ttl_hours = int(os.getenv("SESSION_TTL_HOURS", "12"))
    if not 1 <= session_ttl_hours <= 720:
        raise RuntimeError("SESSION_TTL_HOURS must be between 1 and 720")
    return Settings(
        database_url=database_url,
        secret_key=secret_key,
        flag_hmac_key=flag_hmac_key,
        lab_flags_file=Path(os.getenv("LAB_FLAGS_FILE", "/tmp/cyberarena-lab-flags.json")),
        admin_username=admin_username,
        admin_password=admin_password,
        secure_cookies=os.getenv("COOKIE_SECURE", "false").lower() == "true",
        session_ttl_hours=session_ttl_hours,
        templates_dir=ROOT / "templates" / "platform",
        static_dir=ROOT / "static",
    )
