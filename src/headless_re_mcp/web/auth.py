"""Local token persistence for the web console."""

from __future__ import annotations

import json
import secrets
from contextlib import suppress
from pathlib import Path

from headless_re_mcp.config import Settings, default_config_path


def web_token_path(settings: Settings | None = None) -> Path:
    """Token file lives next to the user config, never inside artifacts."""
    _ = settings
    return default_config_path().parent / "web_token.json"


def load_or_create_web_token(*, path: Path | None = None) -> str:
    """Return the existing local token or create a new 32-byte URL-safe token."""
    token_path = path or web_token_path()
    token_path.parent.mkdir(parents=True, exist_ok=True)
    if token_path.is_file():
        # A truncated or hand-mangled file must regenerate, not crash the
        # console at startup -- the same recovery config.json already gets.
        # Regenerating is safe: this is the server's own credential, so a new
        # value only invalidates stale sessions.
        try:
            raw = json.loads(token_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raw = None
        token = raw.get("token") if isinstance(raw, dict) else None
        if isinstance(token, str) and len(token) >= 24:
            return token
    token = secrets.token_urlsafe(32)
    payload = {
        "token": token,
        "note": "Local loopback web console auth only. Do not commit or share.",
    }
    token_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    with suppress(OSError):
        token_path.chmod(0o600)
    return token


def ensure_web_token(settings: Settings | None = None) -> tuple[str, Path]:
    path = web_token_path(settings)
    return load_or_create_web_token(path=path), path
