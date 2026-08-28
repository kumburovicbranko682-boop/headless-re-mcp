"""Coverage for the log-directory fallback when the preferred dir is unwritable.

``resolve_log_dir`` must never stop a process from starting: if the chosen log
directory cannot be created it falls back to the temp directory. This pins that
fallback (and its best-effort inner mkdir).
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from headless_re_mcp.logging_setup import resolve_log_dir


def test_resolve_log_dir_falls_back_to_tempdir_when_mkdir_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    a_file = tmp_path / "a_file"
    a_file.write_text("not a directory", encoding="utf-8")
    fake_tmp = tmp_path / "tmproot"
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(fake_tmp))

    # The explicit path's parent is a file, so mkdir(parents=True) raises OSError
    # and the resolver must fall back rather than propagate.
    result = resolve_log_dir(explicit=a_file / "sub" / "logs")

    assert result == fake_tmp / "headless-re-mcp" / "logs"
    assert result.is_dir()
