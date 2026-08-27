"""A failed token write must not leave a half-written credential file behind.

load_or_create_web_token creates the token file with O_EXCL and then writes the
JSON payload. If that write throws -- a full disk, an fsync error -- the file it
just created is empty or partial, and leaving it would make the next startup
read a corrupt token file (or, worse, treat an attacker-truncated one as valid).
The failure path deletes the partial file and re-raises so nothing downstream
mistakes a broken write for a usable credential.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.web import auth as web_auth


def test_a_failed_write_removes_the_partial_token_file_and_reraises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "web_token.json"

    def failing_write(fd: int, payload: bytes) -> None:
        # The real writer takes ownership of the fd via fdopen; close it here so
        # the injected failure does not leak the descriptor the caller opened.
        import os

        os.close(fd)
        raise OSError("simulated disk failure during token write")

    monkeypatch.setattr(web_auth, "_write_token_fd", failing_write)

    with pytest.raises(OSError, match="simulated disk failure"):
        web_auth.load_or_create_web_token(path=path)

    # The O_EXCL create succeeded, so the file briefly existed; the cleanup must
    # have removed it rather than leaving an empty credential behind.
    assert not path.exists()
