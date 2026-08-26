"""Local token persistence for the web console."""

from __future__ import annotations

import json
import os
import secrets
import time
from contextlib import suppress
from pathlib import Path
from uuid import uuid4

from headless_re_mcp.config import Settings, default_config_path

_MAX_TOKEN_FILE_BYTES = 16 * 1024


def web_token_path(settings: Settings | None = None) -> Path:
    """Token file lives next to the user config, never inside artifacts."""
    _ = settings
    return default_config_path().parent / "web_token.json"


def _read_web_token(path: Path) -> str | None:
    try:
        if path.is_symlink():
            return None
        with path.open("rb") as stream:
            payload = stream.read(_MAX_TOKEN_FILE_BYTES + 1)
        if len(payload) > _MAX_TOKEN_FILE_BYTES:
            return None
        raw = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict):
        return None
    token = raw.get("token")
    if isinstance(token, str) and 24 <= len(token) <= 4096:
        with suppress(OSError):
            path.chmod(0o600)
        return token
    return None


def _write_token_fd(fd: int, payload: bytes) -> None:
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def _replace_web_token(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}-{uuid4().hex}.tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        _write_token_fd(fd, payload)
        os.replace(temporary, path)
        with suppress(OSError):
            path.chmod(0o600)
    finally:
        with suppress(OSError):
            temporary.unlink()


def load_or_create_web_token(*, path: Path | None = None) -> str:
    """Return the existing local token or create a new 32-byte URL-safe token."""
    token_path = path or web_token_path()
    token_path.parent.mkdir(parents=True, exist_ok=True)
    existing = _read_web_token(token_path)
    if existing is not None:
        return existing
    token = secrets.token_urlsafe(32)
    payload = (
        json.dumps(
            {
                "token": token,
                "note": "Local loopback web console auth only. Do not commit or share.",
            },
            indent=2,
        )
        + "\n"
    ).encode("utf-8")
    try:
        fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Another process may have created the file but not finished its small,
        # fsync-backed write. Wait briefly and use its token so both processes
        # agree on the credential they return.
        for _ in range(20):
            existing = _read_web_token(token_path)
            if existing is not None:
                return existing
            time.sleep(0.01)
        _replace_web_token(token_path, payload)
    else:
        try:
            _write_token_fd(fd, payload)
        except BaseException:
            with suppress(OSError):
                token_path.unlink()
            raise
    return token


def ensure_web_token(settings: Settings | None = None) -> tuple[str, Path]:
    path = web_token_path(settings)
    return load_or_create_web_token(path=path), path
