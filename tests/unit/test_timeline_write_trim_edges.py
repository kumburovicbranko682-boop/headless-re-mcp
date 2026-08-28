"""Edge coverage for the timeline append/trim write path.

``test_timeline_store.py`` and ``test_timeline_under_load.py`` cover the common
append, the byte cap and the read path. These pin three write-side arcs the
wider suite does not reach: the fallback when even the truncated entry will not
fit the byte cap, a trim whose surviving tail fits entirely (the loop exits
without breaking), and the atomic-replace cleanup that removes the partial and
re-raises when the rename fails. A separate file keeps this off the
concurrently edited ``test_timeline_store.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import headless_re_mcp.core.store.timeline as timeline
from headless_re_mcp.core.store.timeline import _trim_timeline, append_session_timeline


def test_append_reports_write_failure_when_even_a_truncated_entry_is_too_big(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Shrink the byte cap below the size of the truncated fallback entry itself,
    # so the second length check fails and append reports the failure rather
    # than writing an entry that would blow the cap on its own.
    monkeypatch.setattr(timeline, "_MAX_BYTES", 10)
    path = tmp_path / "timeline.jsonl"

    entry = append_session_timeline(
        path, event="dump.finished", message="x" * 200, details={"k": "v" * 50}
    )

    assert entry["event"] == "timeline.entry.truncated"
    assert "too small" in entry["write_failed"]
    # Nothing is written when the entry cannot be made to fit.
    assert not path.exists()


def test_trim_keeps_a_tail_that_fits_entirely(tmp_path: Path) -> None:
    path = tmp_path / "timeline.jsonl"
    lines = [b'{"n": 1}\n', b'{"n": 2}\n', b'{"n": 3}\n']
    path.write_bytes(b"".join(lines))

    # A generous budget and a tiny file: every line fits, so the loop runs to
    # completion instead of breaking on the budget or the line ceiling.
    new_size = _trim_timeline(path, reserve=0)

    assert new_size == sum(len(line) for line in lines)
    assert path.read_bytes() == b"".join(lines)


def test_trim_cleans_up_the_partial_and_reraises_when_replace_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "timeline.jsonl"
    path.write_bytes(b'{"n": 1}\n{"n": 2}\n')

    real_replace = Path.replace
    captured: dict[str, Path] = {}

    def _boom(self: Path, target: object) -> Path:
        # Record the partial the trim created, then fail the atomic rename the
        # way a cross-device or permission error would.
        captured["partial"] = self
        raise OSError("rename refused")

    monkeypatch.setattr(Path, "replace", _boom)

    with pytest.raises(OSError, match="rename refused"):
        _trim_timeline(path, reserve=0)

    monkeypatch.setattr(Path, "replace", real_replace)
    partial = captured["partial"]
    assert not partial.exists(), "the failed trim must not leave its .partial behind"
    # The original file is untouched: a failed trim raises rather than losing it.
    assert path.read_bytes() == b'{"n": 1}\n{"n": 2}\n'
