"""JadxClient listing, decompile resolution, and subprocess mapping without jadx.

jadx and its JRE are absent in CI. The export/decompile flows swap in a fake
``_run`` that writes whatever source tree jadx would have produced, and ``_run``
itself is driven with a monkeypatched ``run_bounded`` so its timeout, launch,
and no-output contracts run without launching anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.backends.jadx import client as jadx_client
from headless_re_mcp.backends.jadx.client import (
    JadxClient,
    JadxError,
    _capped_java_listing,
    _class_to_java_path,
)


def _exe(tmp_path: Path) -> Path:
    path = tmp_path / "jadx"
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    return path


def _apk(tmp_path: Path) -> Path:
    path = tmp_path / "app.apk"
    path.write_bytes(b"PK\x03\x04")
    return path


# --- _capped_java_listing ---------------------------------------------------


def test_capped_java_listing_handles_a_missing_root(tmp_path: Path) -> None:
    assert _capped_java_listing(tmp_path / "nope", cap=10) == ([], 0, False)


def test_capped_java_listing_caps_names_and_skips_non_files(tmp_path: Path) -> None:
    root = tmp_path / "out"
    (root / "a").mkdir(parents=True)
    for name in ("A.java", "B.java", "C.java"):
        (root / "a" / name).write_text("x", encoding="utf-8")
    # A directory whose name ends in .java must not be counted as a source file.
    (root / "weird.java").mkdir()
    names, total, has_more = _capped_java_listing(root, cap=2)
    assert total == 3
    assert len(names) == 2 and has_more is True


def test_capped_java_listing_stops_at_the_global_count_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jadx_client, "_MAX_COUNTED_FILES", 2, raising=False)
    root = tmp_path / "out"
    root.mkdir()
    for index in range(4):
        (root / f"C{index}.java").write_text("x", encoding="utf-8")
    _names, total, has_more = _capped_java_listing(root, cap=100)
    assert total == 2 and has_more is True


# --- export_sources ---------------------------------------------------------


def _fake_run(*, code: int = 0, stderr: str = "", writes: dict[str, str] | None = None) -> Any:
    def _run(apk: Path, extra: list[str], out_dir: Path, *, timeout: float) -> tuple[str, str, int]:
        out_dir.mkdir(parents=True, exist_ok=True)
        for rel, text in (writes or {}).items():
            target = out_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        return ("stdout", stderr, code)

    return _run


def test_export_sources_summarizes_the_tree(tmp_path: Path) -> None:
    client = JadxClient(executable=_exe(tmp_path))
    client._run = _fake_run(writes={"sources/com/x/A.java": "class A {}"})  # type: ignore[method-assign]
    result = client.export_sources(_apk(tmp_path), tmp_path / "out")
    assert result["java_file_count"] == 1
    assert result["sources_dir"] is not None
    assert "tool_failed" not in result


def test_export_sources_flags_a_partial_decompile(tmp_path: Path) -> None:
    client = JadxClient(executable=_exe(tmp_path))
    client._run = _fake_run(  # type: ignore[method-assign]
        code=1, stderr="failed on one class", writes={"sources/com/x/A.java": "class A {}"}
    )
    result = client.export_sources(_apk(tmp_path), tmp_path / "out")
    assert result["tool_failed"] is True and result["exit_code"] == 1
    assert "failed on one class" in result["stderr"]


# --- decompile --------------------------------------------------------------


def test_decompile_requires_a_class_name(tmp_path: Path) -> None:
    client = JadxClient(executable=_exe(tmp_path))
    client._run = _fake_run()  # type: ignore[method-assign]
    with pytest.raises(JadxError) as info:
        client.decompile(_apk(tmp_path), tmp_path / "out", "   ")
    assert info.value.code == "invalid_params"


def test_decompile_returns_the_named_class_source(tmp_path: Path) -> None:
    client = JadxClient(executable=_exe(tmp_path))
    client._run = _fake_run(  # type: ignore[method-assign]
        writes={"sources/com/x/A.java": "class A { int v; }"}
    )
    result = client.decompile(_apk(tmp_path), tmp_path / "out", "com.x.A")
    assert result["class_name"] == "com.x.A"
    assert "class A" in result["source"]
    assert result["truncated"] is False


def test_decompile_truncates_a_large_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jadx_client, "_MAX_SOURCE_BYTES", 8, raising=False)
    client = JadxClient(executable=_exe(tmp_path))
    client._run = _fake_run(  # type: ignore[method-assign]
        writes={"sources/com/x/A.java": "class A { /* very long body */ }"}
    )
    result = client.decompile(_apk(tmp_path), tmp_path / "out", "com.x.A")
    assert result["truncated"] is True
    assert len(result["source"]) <= 8


def test_decompile_falls_back_to_a_unique_basename_match(tmp_path: Path) -> None:
    client = JadxClient(executable=_exe(tmp_path))
    # jadx emitted the class under a different package than the dotted name
    # implies, but there is exactly one A.java, so the fallback resolves it.
    client._run = _fake_run(  # type: ignore[method-assign]
        writes={"sources/actual/pkg/A.java": "class A {}"}
    )
    result = client.decompile(_apk(tmp_path), tmp_path / "out", "com.x.A")
    assert result["path"].endswith("A.java")
    assert "class A" in result["source"]


def test_decompile_reports_when_no_sources_were_written(tmp_path: Path) -> None:
    client = JadxClient(executable=_exe(tmp_path))
    # _run creates the output dir but no sources subtree at all.
    client._run = _fake_run(writes={"README.txt": "no java here"})  # type: ignore[method-assign]
    with pytest.raises(JadxError) as info:
        client.decompile(_apk(tmp_path), tmp_path / "out", "com.x.A")
    assert info.value.code == "not_found"


def test_decompile_reports_when_the_basename_is_ambiguous(tmp_path: Path) -> None:
    client = JadxClient(executable=_exe(tmp_path))
    client._run = _fake_run(  # type: ignore[method-assign]
        writes={
            "sources/one/A.java": "class A {}",
            "sources/two/A.java": "class A {}",
        }
    )
    with pytest.raises(JadxError) as info:
        client.decompile(_apk(tmp_path), tmp_path / "out", "com.x.A")
    assert info.value.code == "not_found"


def test_decompile_carries_partial_verdict_from_export(tmp_path: Path) -> None:
    client = JadxClient(executable=_exe(tmp_path))
    client._run = _fake_run(  # type: ignore[method-assign]
        code=1, stderr="partial", writes={"sources/com/x/A.java": "class A {}"}
    )
    result = client.decompile(_apk(tmp_path), tmp_path / "out", "com.x.A")
    assert result["tool_failed"] is True and result["exit_code"] == 1


# --- _class_to_java_path ----------------------------------------------------


def test_class_to_java_path_accepts_smali_form() -> None:
    assert _class_to_java_path("Lcom/x/A;") == Path("com/x/A.java")
    # An inner class folds into its outer file.
    assert _class_to_java_path("com.x.A$Inner") == Path("com/x/A.java")


def test_class_to_java_path_rejects_invalid_characters() -> None:
    with pytest.raises(JadxError) as info:
        _class_to_java_path("com\\x\\A")
    assert info.value.code == "invalid_params"


def test_class_to_java_path_rejects_empty_segments() -> None:
    with pytest.raises(JadxError) as info:
        _class_to_java_path("com..A")
    assert info.value.code == "invalid_params"


# --- _run subprocess mapping ------------------------------------------------


def test_run_rejects_a_non_positive_timeout(tmp_path: Path) -> None:
    client = JadxClient(executable=_exe(tmp_path))
    with pytest.raises(JadxError) as info:
        client._run(_apk(tmp_path), [], tmp_path / "out", timeout=0.0)
    assert info.value.code == "invalid_params"


def test_run_reports_when_jadx_is_not_configured(tmp_path: Path) -> None:
    client = JadxClient(executable=None)
    with pytest.raises(JadxError) as info:
        client._run(_apk(tmp_path), [], tmp_path / "out", timeout=10.0)
    assert info.value.code == "capability_unavailable"


def test_run_reports_a_missing_apk(tmp_path: Path) -> None:
    client = JadxClient(executable=_exe(tmp_path))
    with pytest.raises(JadxError) as info:
        client._run(tmp_path / "gone.apk", [], tmp_path / "out", timeout=10.0)
    assert info.value.code == "not_found"


def test_run_maps_a_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = JadxClient(executable=_exe(tmp_path))

    def _timeout(*_a: Any, **_k: Any) -> Any:
        raise TimedOut(4.0, [55])

    monkeypatch.setattr(jadx_client, "run_bounded", _timeout)
    with pytest.raises(JadxError) as info:
        client._run(_apk(tmp_path), [], tmp_path / "out", timeout=10.0)
    assert info.value.code == "timeout" and info.value.details.get("killed_pids") == [55]


def test_run_maps_a_launch_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = JadxClient(executable=_exe(tmp_path))
    monkeypatch.setattr(
        jadx_client, "run_bounded", lambda *a, **k: (_ for _ in ()).throw(OSError("no java"))
    )
    with pytest.raises(JadxError) as info:
        client._run(_apk(tmp_path), [], tmp_path / "out", timeout=10.0)
    assert info.value.code == "backend_error"


def test_run_raises_when_nonzero_and_no_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = JadxClient(executable=_exe(tmp_path))
    monkeypatch.setattr(jadx_client, "run_bounded", lambda *a, **k: Completed(1, b"", b"boom"))
    with pytest.raises(JadxError) as info:
        client._run(_apk(tmp_path), [], tmp_path / "out", timeout=10.0)
    assert info.value.code == "backend_error"
    assert "no sources" in info.value.message


def test_run_keeps_a_partial_tree_on_nonzero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = JadxClient(executable=_exe(tmp_path))
    out_dir = tmp_path / "out"

    def _partial(cmd: list[str], **_k: Any) -> Completed:
        # A source landed on disk despite the non-zero exit.
        (out_dir / "sources").mkdir(parents=True, exist_ok=True)
        (out_dir / "sources" / "A.java").write_text("class A {}", encoding="utf-8")
        return Completed(1, b"out", b"warned")

    monkeypatch.setattr(jadx_client, "run_bounded", _partial)
    stdout, stderr, code = client._run(_apk(tmp_path), [], out_dir, timeout=10.0)
    assert code == 1 and stderr == "warned"


def test_run_returns_cleanly_on_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = JadxClient(executable=_exe(tmp_path))
    monkeypatch.setattr(jadx_client, "run_bounded", lambda *a, **k: Completed(0, b"done", b""))
    stdout, stderr, code = client._run(_apk(tmp_path), [], tmp_path / "out", timeout=10.0)
    assert code == 0 and stdout == "done"
