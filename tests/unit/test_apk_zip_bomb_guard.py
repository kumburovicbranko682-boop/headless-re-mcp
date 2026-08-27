"""Every APK inflation point must refuse a declared-size bomb up front.

apktool and jadx inflate the archive onto disk; androguard inflates it into
RAM. All three were bounded only by the call timeout, so a central directory
declaring petabytes (the 42.zip shape) filled the disk -- or OOMed the server
-- for minutes before the deadline fired. The central directory is cheap to
read, so the shared guard refuses the bomb before any tool spends a byte,
and an archive whose directory cannot be read at all fails closed too.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError
from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError
from headless_re_mcp.backends.common import zip_guard
from headless_re_mcp.backends.common.zip_guard import ZipExpansionError, check_zip_expansion
from headless_re_mcp.backends.jadx.client import JadxClient, JadxError


def _honest_apk(path: Path, *, members: int = 2, member_bytes: int = 64) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for index in range(members):
            archive.writestr(f"entry-{index}", b"x" * member_bytes)
    return path


def test_the_guard_reads_the_declared_totals_of_an_honest_archive(tmp_path: Path) -> None:
    apk = _honest_apk(tmp_path / "app.apk", members=3, member_bytes=10)
    facts = check_zip_expansion(apk)
    assert facts == {"members": 3, "declared_bytes": 30}


def test_the_guard_refuses_a_declared_size_bomb(tmp_path: Path, monkeypatch: Any) -> None:
    """The bomb never has to exist on disk: the declaration is what is trusted.

    Shrink the cap instead of building gigabytes -- the point is that the
    *declared* uncompressed total is compared, before anything inflates.
    """
    monkeypatch.setattr(zip_guard, "_MAX_DECLARED_BYTES", 100)
    apk = _honest_apk(tmp_path / "bomb.apk", members=2, member_bytes=80)
    with pytest.raises(ZipExpansionError) as caught:
        check_zip_expansion(apk)
    assert caught.value.code == "too_large"
    assert caught.value.details["declared_bytes"] == 160


def test_the_guard_refuses_a_member_count_bomb(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(zip_guard, "_MAX_MEMBERS", 4)
    apk = _honest_apk(tmp_path / "many.apk", members=6, member_bytes=1)
    with pytest.raises(ZipExpansionError) as caught:
        check_zip_expansion(apk)
    assert caught.value.code == "too_large"


def test_the_guard_fails_closed_on_an_unreadable_archive(tmp_path: Path) -> None:
    """A directory that cannot be read is a refusal, not a pass-through.

    None of the downstream tools could decode such a zip either, so refusing
    early loses nothing -- and a crafted archive must not dodge the size
    check by being unparseable to the guard yet palatable to the tool.
    """
    bogus = tmp_path / "bogus.apk"
    bogus.write_bytes(b"PK\x03\x04 not actually a zip")
    with pytest.raises(ZipExpansionError) as caught:
        check_zip_expansion(bogus)
    assert caught.value.code == "invalid_params"


def test_apktool_decode_refuses_the_bomb_before_the_jvm_starts(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """decode must spend nothing on a bomb: no JVM, no output directory."""
    monkeypatch.setattr(zip_guard, "_MAX_DECLARED_BYTES", 100)
    apk = _honest_apk(tmp_path / "bomb.apk", members=2, member_bytes=80)
    fake_tool = tmp_path / "apktool.bat"
    fake_tool.write_text("@echo off\n", encoding="utf-8")

    def never_runs(*_args: Any, **_kwargs: Any) -> tuple[str, str, int]:
        raise AssertionError("a refused APK must not start apktool")

    monkeypatch.setattr("headless_re_mcp.backends.apktool.client._run", never_runs)
    client = ApktoolClient(fake_tool, None)
    out = tmp_path / "decoded"
    with pytest.raises(ApktoolError) as caught:
        client.decode(apk, out)
    assert caught.value.code == "too_large"
    assert not out.exists()


def test_jadx_refuses_the_bomb_before_the_jvm_starts(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The guard sits inside _run, so export_sources and decompile share it."""
    monkeypatch.setattr(zip_guard, "_MAX_DECLARED_BYTES", 100)
    apk = _honest_apk(tmp_path / "bomb.apk", members=2, member_bytes=80)
    fake_tool = tmp_path / "jadx.bat"
    fake_tool.write_text("x", encoding="utf-8")

    def never_runs(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("a refused APK must not start jadx")

    monkeypatch.setattr("headless_re_mcp.backends.jadx.client.run_bounded", never_runs)
    client = JadxClient(fake_tool)
    with pytest.raises(JadxError) as caught:
        client.export_sources(apk, tmp_path / "out")
    assert caught.value.code == "too_large"


def test_androguard_parse_refuses_the_bomb_before_inflating_into_ram(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The refusal lands before the androguard import, let alone the parse.

    Where apktool and jadx fill the disk, androguard decompresses in-process:
    a classes.dex declaring gigabytes OOMs the whole server, not one tool
    call. Forcing availability proves the ordering -- were the guard after
    the import, this environment (no androguard) would raise ImportError
    instead of the too_large envelope.
    """
    monkeypatch.setattr(zip_guard, "_MAX_DECLARED_BYTES", 100)
    apk = _honest_apk(tmp_path / "bomb.apk", members=2, member_bytes=80)
    client = ApkClient()
    client._available = True
    with pytest.raises(ApkError) as caught:
        client.open(apk)
    assert caught.value.code == "too_large"
