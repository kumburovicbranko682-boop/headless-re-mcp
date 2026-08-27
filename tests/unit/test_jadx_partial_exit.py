"""jadx must say when it partially failed but still wrote sources.

jadx exits non-zero when it cannot decompile some classes, yet writes the ones
it managed and leaves a ``// jadx failed to decompile`` stub for the rest. The
client only fails hard when *nothing* lands; a partial run otherwise looked
identical to a clean one. These pin the ``tool_failed`` signal (the same flag the
jsre/wabt CLIs raise for their own partial exits) on both ``export_sources`` and
``decompile`` with a mocked ``_run`` -- no real jadx or JRE needed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jadx.client import JadxClient


def _write_sources(out_dir: Path, body: str) -> None:
    pkg = out_dir / "sources" / "com" / "example"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "Main.java").write_text(body, encoding="utf-8")


def test_export_sources_flags_a_partial_jadx_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = JadxClient(tmp_path / "jadx")
    out = tmp_path / "out"

    def fake_run(
        apk: Path, extra: list[str], out_dir: Path, *, timeout: float
    ) -> tuple[str, str, int]:
        _write_sources(out_dir, "// jadx failed to decompile method x\nclass Main {}")
        return "", "1 class failed to decompile", 1

    monkeypatch.setattr(client, "_run", fake_run)
    result = client.export_sources(tmp_path / "app.apk", out)
    assert result["tool_failed"] is True
    assert result["exit_code"] == 1
    assert result["stderr"] == "1 class failed to decompile"
    # The sources it did write are still reported.
    assert result["java_file_count"] == 1


def test_export_sources_clean_run_has_no_tool_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = JadxClient(tmp_path / "jadx")
    out = tmp_path / "out"

    def fake_run(
        apk: Path, extra: list[str], out_dir: Path, *, timeout: float
    ) -> tuple[str, str, int]:
        _write_sources(out_dir, "class Main {}")
        return "", "", 0

    monkeypatch.setattr(client, "_run", fake_run)
    result = client.export_sources(tmp_path / "app.apk", out)
    assert "tool_failed" not in result
    assert "exit_code" not in result
    assert result["java_file_count"] == 1


def test_decompile_propagates_a_partial_jadx_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = JadxClient(tmp_path / "jadx")
    out = tmp_path / "out"

    def fake_run(
        apk: Path, extra: list[str], out_dir: Path, *, timeout: float
    ) -> tuple[str, str, int]:
        _write_sources(out_dir, "// jadx failed to decompile method x\nclass Main {}")
        return "", "boom", 1

    monkeypatch.setattr(client, "_run", fake_run)
    result = client.decompile(tmp_path / "app.apk", out, "com.example.Main")
    # The requested class is returned, but the partial-run flag rides along so the
    # caller does not read a "// jadx failed to decompile" stub as clean output.
    assert result["class_name"] == "com.example.Main"
    assert "class Main" in result["source"]
    assert result["tool_failed"] is True
    assert result["exit_code"] == 1


def test_decompile_clean_run_has_no_tool_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = JadxClient(tmp_path / "jadx")
    out = tmp_path / "out"

    def fake_run(
        apk: Path, extra: list[str], out_dir: Path, *, timeout: float
    ) -> tuple[str, str, int]:
        _write_sources(out_dir, "class Main {}")
        return "", "", 0

    monkeypatch.setattr(client, "_run", fake_run)
    result = client.decompile(tmp_path / "app.apk", out, "com.example.Main")
    assert "tool_failed" not in result
    assert "class Main" in result["source"]
