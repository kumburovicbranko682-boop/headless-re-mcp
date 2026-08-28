"""Pin the ``classify_target`` contract that extension beats magic bytes.

``classify_target`` documents "extension first ... then magic bytes for files
named without one": the suffix is the caller's stated intent and wins over
whatever the file actually contains. Every other classification test uses
fixtures whose extension and content agree (or whose content has no recognised
magic), so the *precedence* between the two signals is never exercised. That
leaves the ordering inert -- swapping the magic sniff ahead of the suffix check,
or dropping the suffix short-circuit so every path is opened, would keep the
existing suite green while silently re-routing hostile or mislabelled inputs to
the wrong backend line (PE vs. APK vs. WEB).

These tests make the ordering load-bearing by giving each fixture an extension
that disagrees with its bytes, plus paths that do not exist on disk so the
suffix branch must decide the line before any read is attempted.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.session import classify_target

_MZ = b"MZ\x90\x00" + b"\x00" * 8
_WASM = b"\x00asm\x01\x00\x00\x00"


def _real_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


@pytest.mark.parametrize("suffix", [".js", ".mjs", ".cjs", ".wasm", ".html", ".htm", ".har"])
def test_a_web_suffix_beats_pe_magic_in_the_file(tmp_path: Path, suffix: str) -> None:
    """A web-labelled file whose bytes are a PE still routes to the web line."""

    target = tmp_path / f"bundle{suffix}"
    target.write_bytes(_MZ)
    assert classify_target(target) is TargetKind.WEB


def test_a_web_suffix_beats_a_real_android_package_inside(tmp_path: Path) -> None:
    """A genuine APK renamed to .wasm is honoured as the caller's web intent."""

    disguised = _real_apk(tmp_path / "actually_an_apk.wasm")
    assert classify_target(disguised) is TargetKind.WEB


@pytest.mark.parametrize("suffix", [".apk", ".aab", ".apks", ".xapk"])
def test_an_apk_suffix_beats_wasm_magic_in_the_file(tmp_path: Path, suffix: str) -> None:
    """An apk-labelled file whose bytes are wasm still routes to the Android line."""

    target = tmp_path / f"trick{suffix}"
    target.write_bytes(_WASM)
    assert classify_target(target) is TargetKind.APK


def test_an_apk_suffix_beats_a_plain_pe_inside(tmp_path: Path) -> None:
    target = tmp_path / "wrapper.apk"
    target.write_bytes(_MZ)
    assert classify_target(target) is TargetKind.APK


def test_an_apk_suffix_classifies_without_reading_the_file(tmp_path: Path) -> None:
    """The suffix short-circuits before the magic read, so a missing file still
    routes to the Android line rather than degrading to the PE fallback that an
    OSError would otherwise trigger."""

    ghost = tmp_path / "never_created.apk"
    assert not ghost.exists()
    assert classify_target(ghost) is TargetKind.APK


def test_a_web_suffix_classifies_without_reading_the_file(tmp_path: Path) -> None:
    ghost = tmp_path / "never_created.js"
    assert not ghost.exists()
    assert classify_target(ghost) is TargetKind.WEB


def test_an_unsuffixed_missing_file_falls_back_to_pe(tmp_path: Path) -> None:
    """With no suffix to state intent, an unreadable path takes the documented
    PE fallback -- the branch that keeps the original "not a PE file" error."""

    ghost = tmp_path / "never_created"
    assert not ghost.exists()
    assert classify_target(ghost) is TargetKind.PE
