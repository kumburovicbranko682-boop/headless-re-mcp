"""A jadx run that choked on some classes must not read as a clean decompile.

jadx routinely exits non-zero on a per-class failure while still writing a
usable tree for everything else, so the backend keeps the output rather than
failing. But the summary then looked exactly like a whole-APK success: no exit
status, no stderr. These lock in that a non-zero exit with a tree is surfaced
(exit_code / tool_failed / stderr) through both apk.export_sources and the
single-class apk.decompile, while a clean run stays free of that noise and a
run that wrote nothing still raises.
"""

from __future__ import annotations

import ast
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.jadx.client import JadxClient, JadxError
from headless_re_mcp.tools.apk import build_apk_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_apk_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def _jadx(tmp_path: Path) -> tuple[JadxClient, Path, Path]:
    tool = tmp_path / "jadx"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    apk = tmp_path / "app.apk"
    # A real (tiny) zip: _run now refuses a non-zip APK before the JVM launch,
    # so the bare "PK\x03\x04" magic no longer stands in for an archive here.
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
    out = tmp_path / "out"
    return JadxClient(tool), apk, out


def _writes_one_class(
    out: Path, *, code: int, stderr: bytes
) -> Callable[..., Completed]:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        srcdir = out / "sources" / "com" / "example"
        srcdir.mkdir(parents=True, exist_ok=True)
        (srcdir / "Main.java").write_text("class Main {}", encoding="utf-8")
        return Completed(code, b"", stderr)

    return fake_run


def test_export_sources_surfaces_a_nonzero_exit_with_a_partial_tree(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)
    fake_run = _writes_one_class(out, code=1, stderr=b"ERROR: failed to decompile 3 classes")

    with patch("headless_re_mcp.backends.jadx.client.run_bounded", fake_run):
        payload = client.export_sources(apk, out)

    assert payload["java_file_count"] == 1
    assert payload["exit_code"] == 1
    assert payload["tool_failed"] is True
    assert payload["stderr"] == "ERROR: failed to decompile 3 classes"


def test_export_sources_clean_run_carries_no_failure_fields(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)
    fake_run = _writes_one_class(out, code=0, stderr=b"INFO: done")

    with patch("headless_re_mcp.backends.jadx.client.run_bounded", fake_run):
        payload = client.export_sources(apk, out)

    assert payload["java_file_count"] == 1
    assert "exit_code" not in payload
    assert "tool_failed" not in payload
    assert "stderr" not in payload


def test_export_sources_still_raises_when_nothing_landed(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        out.mkdir(parents=True, exist_ok=True)
        return Completed(2, b"", b"fatal: bad dex")

    with (
        patch("headless_re_mcp.backends.jadx.client.run_bounded", fake_run),
        pytest.raises(JadxError) as caught,
    ):
        client.export_sources(apk, out)

    assert caught.value.code == "backend_error"
    assert caught.value.details.get("exit_code") == 2


def test_decompile_propagates_the_partial_failure_signal(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)
    fake_run = _writes_one_class(out, code=1, stderr=b"partial failure")

    with patch("headless_re_mcp.backends.jadx.client.run_bounded", fake_run):
        payload = client.decompile(apk, out, "com.example.Main")

    assert payload["class_name"] == "com.example.Main"
    assert payload["source"] == "class Main {}"
    assert payload["exit_code"] == 1
    assert payload["tool_failed"] is True
    assert payload["stderr"] == "partial failure"


def test_decompile_clean_run_carries_no_failure_fields(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)
    fake_run = _writes_one_class(out, code=0, stderr=b"")

    with patch("headless_re_mcp.backends.jadx.client.run_bounded", fake_run):
        payload = client.decompile(apk, out, "com.example.Main")

    assert payload["source"] == "class Main {}"
    assert "exit_code" not in payload
    assert "tool_failed" not in payload
    assert "stderr" not in payload


def test_surfaced_stderr_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from headless_re_mcp.backends.jadx import client as mod

    monkeypatch.setattr(mod, "_MAX_STDERR", 16)
    client, apk, out = _jadx(tmp_path)
    fake_run = _writes_one_class(out, code=1, stderr=b"e" * 5000)

    with patch("headless_re_mcp.backends.jadx.client.run_bounded", fake_run):
        payload = client.export_sources(apk, out)

    assert payload["stderr"] == "e" * 16


def test_export_sources_refuses_a_non_zip_apk_before_launching_jadx(tmp_path: Path) -> None:
    """A non-zip APK is invalid_params, refused before the JVM starts.

    jadx only ever decompiles an APK-kind session target, but the on-disk file
    is not re-checked against the session sha before the call, so a swapped or
    suffix-only-detected file can reach jadx as a non-zip. Handed one it still
    started a JVM and failed with "jadx produced no sources"; the precheck turns
    that into a precise invalid_params up front, the same guard apktool applies.
    """
    tool = tmp_path / "jadx"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"this is a truncated download, not a zip archive")
    out = tmp_path / "out"
    client = JadxClient(tool)

    def _must_not_run(cmd: list[str], **kwargs: Any) -> Completed:
        raise AssertionError("run_bounded ran for a non-zip APK")

    with (
        patch("headless_re_mcp.backends.jadx.client.run_bounded", _must_not_run),
        pytest.raises(JadxError) as caught,
    ):
        client.export_sources(apk, out)
    assert caught.value.code == "invalid_params"
    assert not out.exists()


def test_docstrings_name_the_partial_failure_fields() -> None:
    for name in ("apk.decompile", "apk.export_sources"):
        doc = _tool_docstring(name)
        assert "exit_code" in doc
        assert "tool_failed" in doc
