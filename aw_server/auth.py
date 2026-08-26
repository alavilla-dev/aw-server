"""User + API-token store for CEPEM Watch multi-user mode.

Tokens are random, shown once at creation, and stored only as a SHA-256 hash.
The store is a small JSON file in the aw-server config directory:

    { "users": { "<username>": {
          "token_sha256": "<hex>", "role": "user"|"admin", "created": "<iso8601>"
    } } }

This is intentionally simple (file-backed, admin-provisioned) — adequate for an
internal CEPEM deployment behind TLS/VPN. See MULTIUSER_DESIGN.md.
"""
import hashlib
import hmac
import json
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from aw_core.dirs import get_config_dir

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
PREFIX_SEP = "/"  # internal bucket-id namespace separator (never sent over the wire)


def _users_path(testing: bool = False) -> Path:
    fname = "users-testing.json" if testing else "users.json"
    return Path(get_config_dir("aw-server")) / fname


def load_users(testing: bool = False) -> Dict[str, dict]:
    path = _users_path(testing)
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("users", {})


def save_users(users: Dict[str, dict], testing: bool = False) -> None:
    path = _users_path(testing)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"users": users}, f, indent=2, sort_keys=True)
    tmp.replace(path)  # atomic on the same filesystem


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _validate_username(username: str) -> None:
    if not USERNAME_RE.match(username):
        raise ValueError(
            f"Invalid username {username!r}: use 1-64 chars of [A-Za-z0-9_-]"
        )


def add_user(username: str, role: str = "user", testing: bool = False) -> str:
    """Create a user and return the freshly generated plaintext token (shown once)."""
    _validate_username(username)
    if role not in ("user", "admin"):
        raise ValueError("role must be 'user' or 'admin'")
    users = load_users(testing)
    if username in users:
        raise ValueError(f"User {username!r} already exists")
    token = secrets.token_urlsafe(32)
    users[username] = {
        "token_sha256": hash_token(token),
        "role": role,
        "created": datetime.now(timezone.utc).isoformat(),
    }
    save_users(users, testing)
    return token


def reissue_token(username: str, testing: bool = False) -> str:
    """Rotate a user's token; returns the new plaintext token."""
    users = load_users(testing)
    if username not in users:
        raise ValueError(f"No such user {username!r}")
    token = secrets.token_urlsafe(32)
    users[username]["token_sha256"] = hash_token(token)
    save_users(users, testing)
    return token


def revoke_user(username: str, testing: bool = False) -> None:
    users = load_users(testing)
    if username not in users:
        raise ValueError(f"No such user {username!r}")
    del users[username]
    save_users(users, testing)


def list_users(testing: bool = False) -> List[dict]:
    users = load_users(testing)
    return [
        {"username": u, "role": meta.get("role", "user"), "created": meta.get("created")}
        for u, meta in sorted(users.items())
    ]


def verify_token(token: str, testing: bool = False) -> Optional[dict]:
    """Return {'username', 'role'} for a valid token, else None (constant-time)."""
    if not token:
        return None
    candidate = hash_token(token)
    match: Optional[dict] = None
    # Iterate all users with constant-time compares so timing doesn't leak which
    # (if any) user matched.
    for username, meta in load_users(testing).items():
        stored = meta.get("token_sha256", "")
        if hmac.compare_digest(candidate, stored):
            match = {"username": username, "role": meta.get("role", "user")}
    return match
