"""jadx paths the partial-decompile and path-safety suites do not reach.

The partial-decompile suite pins the exit-code/tool_failed surfacing; here the
focus is the ``_capped_java_listing`` bounds, the single-class lookup falling
back to a unique simple-name match (and refusing an ambiguous or missing one),
the source read error, and ``_run``'s capability/not_found/timeout/backend_error
mapping. ``run_bounded`` is faked so no JRE is needed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.backends.jadx import client as jadx_client
from headless_re_mcp.backends.jadx.client import (
    JadxClient,
    JadxError,
    _capped_java_listing,
)

_RUN = "headless_re_mcp.backends.jadx.client.run_bounded"


def _jadx(tmp_path: Path) -> tuple[JadxClient, Path, Path]:
    tool = tmp_path / "jadx"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    return JadxClient(tool), apk, tmp_path / "out"


def _writes(out: Path, files: dict[str, str], *, code: int = 0):
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        for rel, body in files.items():
            path = out / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        return Completed(code, b"", b"")

    return fake_run


# ---------------------------------------------------------------------------
# _capped_java_listing
# ---------------------------------------------------------------------------
def test_capped_java_listing_handles_a_missing_root(tmp_path: Path) -> None:
    assert _capped_java_listing(tmp_path / "nope", cap=10) == ([], 0, False)


def test_capped_java_listing_flags_has_more_over_the_cap(tmp_path: Path) -> None:
    for i in range(3):
        (tmp_path / f"C{i}.java").write_text("x", encoding="utf-8")
    # A directory whose name matches the glob must be skipped, not counted.
    (tmp_path / "weird.java").mkdir()
    names, total, has_more = _capped_java_listing(tmp_path, cap=1)
    assert total == 3
    assert len(names) == 1
    assert has_more is True


def test_capped_java_listing_stops_at_the_counted_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jadx_client, "_MAX_COUNTED_FILES", 2)
    for i in range(4):
        (tmp_path / f"C{i}.java").write_text("x", encoding="utf-8")
    names, total, has_more = _capped_java_listing(tmp_path, cap=10)
    assert total == 2
    assert has_more is True


# ---------------------------------------------------------------------------
# decompile lookup
# ---------------------------------------------------------------------------
def test_decompile_requires_a_class_name(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)
    with pytest.raises(JadxError) as caught:
        client.decompile(apk, out, "   ")
    assert caught.value.code == "invalid_params"


def test_decompile_falls_back_to_a_unique_simple_name_match(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)
    # jadx emitted Main.java somewhere other than com/example, so the exact
    # dotted path misses but the unique simple-name match is taken.
    fake = _writes(out, {"sources/relocated/Main.java": "class Main {}"})
    with patch(_RUN, fake):
        payload = client.decompile(apk, out, "com.example.Main")
    assert payload["source"] == "class Main {}"
    assert payload["path"].endswith("relocated/Main.java")


def test_decompile_not_found_when_no_match(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)
    fake = _writes(out, {"sources/pkg/Other.java": "class Other {}"})
    with patch(_RUN, fake), pytest.raises(JadxError) as caught:
        client.decompile(apk, out, "com.example.Main")
    assert caught.value.code == "not_found"
    assert caught.value.details["class_name"] == "com.example.Main"


def test_decompile_not_found_when_the_simple_name_is_ambiguous(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)
    fake = _writes(
        out,
        {
            "sources/a/Main.java": "class Main {}",
            "sources/b/Main.java": "class Main {}",
        },
    )
    with patch(_RUN, fake), pytest.raises(JadxError) as caught:
        client.decompile(apk, out, "com.example.Main")
    # Two candidates -- refuse rather than guess which one the caller meant.
    assert caught.value.code == "not_found"


def test_decompile_maps_a_source_read_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, apk, out = _jadx(tmp_path)
    fake = _writes(out, {"sources/com/example/Main.java": "class Main {}"})
    real_open = Path.open

    def guarded_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        mode = args[0] if args else kwargs.get("mode", "r")
        if "b" in mode and "r" in mode:
            raise OSError("disk gone")
        return real_open(self, *args, **kwargs)

    with patch(_RUN, fake):
        monkeypatch.setattr(Path, "open", guarded_open)
        with pytest.raises(JadxError) as caught:
            client.decompile(apk, out, "com.example.Main")
    assert caught.value.code == "backend_error"
    assert "failed to read source" in caught.value.message


# ---------------------------------------------------------------------------
# _run error contracts
# ---------------------------------------------------------------------------
def test_run_rejects_a_non_positive_timeout(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)
    with pytest.raises(JadxError) as caught:
        client.export_sources(apk, out, timeout=0)
    assert caught.value.code == "invalid_params"


def test_run_requires_jadx(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    with pytest.raises(JadxError) as caught:
        JadxClient(None).export_sources(apk, tmp_path / "out")
    assert caught.value.code == "capability_unavailable"


def test_run_missing_apk_is_not_found(tmp_path: Path) -> None:
    client, _apk, out = _jadx(tmp_path)
    with pytest.raises(JadxError) as caught:
        client.export_sources(tmp_path / "ghost.apk", out)
    assert caught.value.code == "not_found"


def test_run_maps_timeout_with_killed_pids(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)

    def _boom(*_a: Any, **_k: Any) -> Completed:
        raise TimedOut(9.0, [77])

    with patch(_RUN, _boom), pytest.raises(JadxError) as caught:
        client.export_sources(apk, out)
    assert caught.value.code == "timeout"
    assert caught.value.details["killed_pids"] == [77]


def test_run_maps_oserror_to_backend_error(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)

    def _boom(*_a: Any, **_k: Any) -> Completed:
        raise OSError("no such file")

    with patch(_RUN, _boom), pytest.raises(JadxError) as caught:
        client.export_sources(apk, out)
    assert caught.value.code == "backend_error"
