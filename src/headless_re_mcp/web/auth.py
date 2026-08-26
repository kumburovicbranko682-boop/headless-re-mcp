"""Local token persistence for the web console."""

from __future__ import annotations

import json
import os
import secrets
import tempfile
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
        try:
            raw = json.loads(token_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            raw = None
        if isinstance(raw, dict):
            candidate = raw.get("token")
            if isinstance(candidate, str) and len(candidate) >= 24:
                with suppress(OSError):
                    token_path.chmod(0o600)
                return candidate
    token: str = str(secrets.token_urlsafe(32))
    payload = {
        "token": token,
        "note": "Local loopback web console auth only. Do not commit or share.",
    }
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=token_path.parent,
            prefix=f".{token_path.name}-",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(json.dumps(payload, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, token_path)
        temporary = None
    finally:
        if temporary is not None:
            with suppress(OSError):
                temporary.unlink()
    with suppress(OSError):
        token_path.chmod(0o600)
    return token


def ensure_web_token(settings: Settings | None = None) -> tuple[str, Path]:
    path = web_token_path(settings)
    return load_or_create_web_token(path=path), path
