"""apktool live repackaging gate: real APK -> smali -> edit -> real APK.

Every other apktool test drives a fake ``_run`` or a stub tree on disk; nothing
launches the real apktool CLI, so ``ApktoolClient.decode``/``build`` -- the
subprocess launch, the ``-r`` flag, the smali-dir discovery, the rebuilt-zip
validation -- are never exercised end to end. This gate builds a real
(hand-assembled) APK, baksmali's it with the actual apktool binary, edits the
smali, rebuilds, and decodes the rebuilt package again to prove the edit made it
through the smali -> dex -> smali round trip. That is the whole point of the
repackaging line, and until now no test proved it against the real tool.

apktool needs a JRE; with neither apktool nor the JRE present the gate skips
loudly rather than passing silently (skip != pass). The fixture is the same
dependency-free minimal APK the jadx gate uses -- one class,
``com.example.gate.Secret``, with ``decrypt``/``caller`` and the string literal
``gate-secret-string`` -- so no Android SDK (aapt2/d8) is required. Resource
decoding needs an aapt2-built ``resources.arsc`` that a hosted runner cannot
produce, so the gate decodes with ``no_resources=True``; the DEX <-> smali round
trip it exercises is the core of the line.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apktool import ApktoolClient, ApktoolError

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_BUILDER = _PROJECT_ROOT / "fixtures" / "android" / "build_min_apk.py"
_SKIP_NO_APKTOOL = (
    "apktool not configured (HEADLESS_RE_APKTOOL/PATH) — live gate not run (skip != pass)"
)
_SECRET_SMALI = "Secret.smali"
_ORIGINAL_STRING = "gate-secret-string"


def _load_builder() -> object:
    spec = importlib.util.spec_from_file_location("_apktool_min_apk_builder", _BUILDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _discover_apktool() -> Path | None:
    candidate = os.environ.get("HEADLESS_RE_APKTOOL")
    if candidate and Path(candidate).is_file():
        return Path(candidate)
    for name in ("apktool", "apktool.bat"):
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


def _client_or_skip() -> ApktoolClient:
    apktool = _discover_apktool()
    if apktool is None:
        pytest.skip(_SKIP_NO_APKTOOL)
    client = ApktoolClient(apktool, None)
    if not client.available:
        pytest.skip(f"apktool path is not a file: {apktool} — live gate not run (skip != pass)")
    return client


def _build_apk(tmp_path: Path) -> Path:
    builder = _load_builder()
    apk = tmp_path / "gate.apk"
    builder.build_apk(apk)  # type: ignore[attr-defined]
    assert apk.is_file() and apk.stat().st_size > 0
    return apk


def _read_secret_smali(decoded_dir: Path) -> Path:
    matches = list(decoded_dir.rglob(_SECRET_SMALI))
    assert matches, f"{_SECRET_SMALI} not produced under {decoded_dir}"
    return matches[0]


@pytest.mark.integration
def test_apktool_decode_build_roundtrip(tmp_path: Path) -> None:
    client = _client_or_skip()
    apk = _build_apk(tmp_path)

    # decode: the DEX is baksmali'd into a real smali tree the client reports.
    decoded = client.decode(apk, tmp_path / "decoded", timeout=300.0, no_resources=True)
    assert decoded["smali_dirs"] == ["smali"], decoded
    assert decoded["has_resources"] is False, decoded
    assert Path(decoded["manifest"]).is_file(), decoded

    smali = _read_secret_smali(tmp_path / "decoded")
    assert smali.as_posix().endswith("smali/com/example/gate/Secret.smali"), smali
    text = smali.read_text(encoding="utf-8")
    assert ".method public static decrypt" in text, text
    assert ".method public static caller" in text, text
    assert _ORIGINAL_STRING in text, text

    # build: the edited-or-not tree re-assembles into a genuine (unsigned) APK.
    built = client.build(tmp_path / "decoded", tmp_path / "rebuilt.apk", timeout=300.0)
    assert built["signed"] is False, built
    assert built["size"] > 0, built
    rebuilt = Path(built["apk"])
    assert zipfile.is_zipfile(rebuilt), built
    with zipfile.ZipFile(rebuilt) as archive:
        assert "classes.dex" in archive.namelist(), archive.namelist()

    # Decoding the rebuilt APK must surface the same class: this proves the smali
    # was assembled back into a valid DEX, not merely copied through.
    redecoded = client.decode(rebuilt, tmp_path / "decoded2", timeout=300.0, no_resources=True)
    assert redecoded["smali_dirs"] == ["smali"], redecoded
    assert _ORIGINAL_STRING in _read_secret_smali(tmp_path / "decoded2").read_text(encoding="utf-8")


@pytest.mark.integration
def test_apktool_edit_smali_survives_rebuild(tmp_path: Path) -> None:
    """decode -> edit smali -> build must carry the edit into the new DEX.

    A repackaging tool that could only pass bytes through unchanged would be
    useless; the edit is the point. Patch the string constant in the smali,
    rebuild, and decode the result: the new constant must be present and the old
    one gone, so the change genuinely round-tripped through smali -> dex -> smali.
    """
    client = _client_or_skip()
    apk = _build_apk(tmp_path)

    client.decode(apk, tmp_path / "decoded", timeout=300.0, no_resources=True)
    smali = _read_secret_smali(tmp_path / "decoded")
    original = smali.read_text(encoding="utf-8")
    assert _ORIGINAL_STRING in original
    patched = "patched-by-gate"
    smali.write_text(original.replace(_ORIGINAL_STRING, patched), encoding="utf-8")

    client.build(tmp_path / "decoded", tmp_path / "rebuilt.apk", timeout=300.0)
    client.decode(tmp_path / "rebuilt.apk", tmp_path / "decoded2", timeout=300.0, no_resources=True)
    result = _read_secret_smali(tmp_path / "decoded2").read_text(encoding="utf-8")
    assert patched in result, result
    assert _ORIGINAL_STRING not in result, result


@pytest.mark.integration
def test_apktool_build_rejects_non_decode_directory(tmp_path: Path) -> None:
    """build must refuse a directory that is not an apktool decode output.

    With the real tool configured, a tree lacking AndroidManifest.xml is a caller
    mistake, not a backend failure: the client rejects it as ``invalid_params``
    before spending a JVM startup, the same fail-fast shape decode uses for a
    non-zip input.
    """
    client = _client_or_skip()
    stray = tmp_path / "not_a_decode"
    stray.mkdir()
    (stray / "smali").mkdir()
    with pytest.raises(ApktoolError) as excinfo:
        client.build(stray, tmp_path / "out.apk", timeout=300.0)
    assert excinfo.value.code == "invalid_params", excinfo.value.code
