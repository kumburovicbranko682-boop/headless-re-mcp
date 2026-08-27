"""Fail-closed cleanup for the persona index atomic write-back.

``PersonaStore._write_index`` stages the index to a sibling ``.tmp`` and then
atomically ``replace``s it into place. If the rename (or the staging write)
fails, the exception must reach the caller *and* the partial ``.tmp`` must not
be left beside the real index, matching the same partial-cleanup invariant the
timeline and unpack-session write paths hold. A separate file keeps this off
the concurrently edited ``test_agent_personas.py`` / ``_guards.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.agent.personas import DEFAULT_PERSONA_ID, PersonaStore


def test_write_index_cleans_up_the_tmp_and_reraises_when_replace_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = PersonaStore(tmp_path)
    index = tmp_path / "index.json"
    original = index.read_bytes()

    def _boom(self: Path, target: object) -> Path:
        raise OSError("rename refused")

    monkeypatch.setattr(Path, "replace", _boom)

    with pytest.raises(OSError, match="rename refused"):
        store._write_index({"current": DEFAULT_PERSONA_ID, "items": {}})

    monkeypatch.undo()
    assert not (
        tmp_path / "index.tmp"
    ).exists(), "a failed index write-back must not strand its .tmp"
    # The seeded index survives: a failed write raises rather than losing it.
    assert index.read_bytes() == original


def test_write_index_cleans_up_when_the_staging_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = PersonaStore(tmp_path)

    real_write_text = Path.write_text

    def _fail_tmp_write(
        self: Path, *args: object, **kwargs: object
    ) -> int:
        if self.name == "index.tmp":
            # Leave a partial behind (as a truncated/interrupted write would)
            # before failing, so the cleanup has a real file to remove.
            self.write_bytes(b'{"partial":')
            raise OSError("disk full")
        return real_write_text(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "write_text", _fail_tmp_write)
    assert not (tmp_path / "index.tmp").exists()

    with pytest.raises(OSError, match="disk full"):
        store._write_index({"current": DEFAULT_PERSONA_ID, "items": {}})

    monkeypatch.undo()
    assert not (
        tmp_path / "index.tmp"
    ).exists(), "the partial staged before the failure must be cleaned up"
