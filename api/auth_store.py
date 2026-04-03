import base64
import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path


AUTH_DIR = Path(__file__).resolve().parent.parent / "data"
USERS_FILE = AUTH_DIR / "users.json"
SECRET_FILE = AUTH_DIR / "auth_secret.txt"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode((data + pad).encode("utf-8"))


def _ensure_auth_dir():
    AUTH_DIR.mkdir(parents=True, exist_ok=True)


def _load_users() -> dict:
    _ensure_auth_dir()
    if not USERS_FILE.exists():
        return {"users": {}}
    try:
        return json.loads(USERS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"users": {}}


def _save_users(data: dict):
    _ensure_auth_dir()
    USERS_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _get_secret() -> bytes:
    _ensure_auth_dir()
    if not SECRET_FILE.exists():
        SECRET_FILE.write_text(secrets.token_hex(32), encoding="utf-8")
    return SECRET_FILE.read_text(encoding="utf-8").strip().encode("utf-8")


def _hash_password(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return digest.hex()


def register_user(username: str, password: str):
    username = username.strip()
    if len(username) < 3:
        raise ValueError("username too short")
    if len(password) < 6:
        raise ValueError("password too short")
    db = _load_users()
    users = db.setdefault("users", {})
    if username in users:
        raise ValueError("username already exists")
    salt_hex = secrets.token_hex(16)
    users[username] = {
        "salt": salt_hex,
        "password_hash": _hash_password(password, salt_hex),
        "created_at": int(time.time()),
    }
    _save_users(db)


def verify_user(username: str, password: str) -> bool:
    db = _load_users()
    user = db.get("users", {}).get(username)
    if not user:
        return False
    expected = user.get("password_hash", "")
    actual = _hash_password(password, user.get("salt", ""))
    return hmac.compare_digest(expected, actual)


def issue_token(username: str, ttl_s: int = 60 * 60 * 24) -> str:
    exp = int(time.time()) + ttl_s
    payload = f"{username}.{exp}".encode("utf-8")
    sig = hmac.new(_get_secret(), payload, hashlib.sha256).digest()
    return f"{_b64url_encode(payload)}.{_b64url_encode(sig)}"


def verify_token(token: str) -> str:
    if "." not in token:
        raise ValueError("invalid token format")
    payload_b64, sig_b64 = token.split(".", 1)
    payload = _b64url_decode(payload_b64)
    sig = _b64url_decode(sig_b64)
    expected_sig = hmac.new(_get_secret(), payload, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected_sig):
        raise ValueError("invalid token signature")
    raw = payload.decode("utf-8")
    if "." not in raw:
        raise ValueError("invalid token payload")
    username, exp_str = raw.rsplit(".", 1)
    if int(exp_str) < int(time.time()):
        raise ValueError("token expired")
    return username
