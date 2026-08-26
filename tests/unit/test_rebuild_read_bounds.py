from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core import service_unpack
from headless_re_mcp.unpack.pe_rebuild import PeRebuildError


def test_rebuild_dump_growth_is_detected_after_a_bounded_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dump = tmp_path / "dump.bin"
    dump.write_bytes(b"MZ00")
    requested: list[int] = []
    real_open = Path.open

    class GrowingReader:
        def __init__(self, path: Path, *args: Any, **kwargs: Any) -> None:
            self.stream = real_open(path, *args, **kwargs)

        def __enter__(self) -> GrowingReader:
            self.stream.__enter__()
            return self

        def __exit__(self, *args: Any) -> Any:
            return self.stream.__exit__(*args)

        def fileno(self) -> int:
            return self.stream.fileno()

        def read(self, size: int = -1) -> bytes:
            requested.append(size)
            return b"x" * size

    def growing_open(path: Path, *args: Any, **kwargs: Any) -> GrowingReader:
        return GrowingReader(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", growing_open)
    monkeypatch.setattr(
        service_unpack,
        "rebuild_would_exhaust_memory",
        lambda _size: (False, 0, 1024 * 1024),
    )

    with pytest.raises(PeRebuildError, match="changed size"):
        service_unpack._read_dump_for_rebuild(dump)

    assert requested == [dump.stat().st_size + 1]


def test_rebuild_refusal_does_not_read_the_open_dump(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dump = tmp_path / "dump.bin"
    dump.write_bytes(b"MZ00")

    monkeypatch.setattr(
        service_unpack,
        "rebuild_would_exhaust_memory",
        lambda size: (True, size * 4, 1),
    )
    raw, refusal = service_unpack._read_dump_for_rebuild(dump)

    assert raw is None
    assert refusal is not None
    assert refusal.error is not None
    assert refusal.error.code == "dump_too_large"
