"""Pin the web-token writer's fail-closed cleanup on a partial write.

``load_or_create_web_token`` creates the token file with ``O_CREAT | O_EXCL``
before writing it. If the write itself fails, the freshly created (and still
empty) file must be removed and the error re-raised, rather than leaving a
zero-byte file behind that a later reader would treat as a present-but-invalid
credential. The happy paths run through ``test_web_console``; this pins the
write-failure branch, which a healthy filesystem never exercises on its own.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from headless_re_mcp.web import auth as auth_mod
from headless_re_mcp.web.auth import load_or_create_web_token


def test_a_failed_write_removes_the_partial_token_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_path = tmp_path / "web_token.json"

    class _WriteFailed(RuntimeError):
        pass

    def _boom(fd: int, payload: bytes) -> None:
        os.close(fd)
        raise _WriteFailed("disk went away mid-write")

    monkeypatch.setattr(auth_mod, "_write_token_fd", _boom)

    with pytest.raises(_WriteFailed):
        load_or_create_web_token(path=token_path)

    assert not token_path.exists()


def test_a_created_token_is_reused_on_the_next_call(tmp_path: Path) -> None:
    token_path = tmp_path / "web_token.json"
    first = load_or_create_web_token(path=token_path)
    second = load_or_create_web_token(path=token_path)
    assert first == second
    assert 24 <= len(first) <= 4096
