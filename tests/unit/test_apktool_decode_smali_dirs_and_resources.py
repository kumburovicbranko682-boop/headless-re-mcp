"""apktool.decode: how it derives smali_dirs and has_resources.

The existing decode-fields test builds one ``smali`` directory and no ``res``,
so it pins ``smali_dirs == ["smali"]`` and ``has_resources is False`` -- and
that homogeneous tree renders every discriminator in

    smali_dirs = sorted(str(p.name) for p in out_dir.glob("smali*") if p.is_dir())
    ...
    "has_resources": (out_dir / "res").is_dir()

inert. A single directory cannot tell whether a real multi-dex tree
(``smali``, ``smali_classes2``, ``smali_classes3``) is collected whole and
sorted, whether the ``smali*`` glob keeps out ``original`` / ``unknown`` /
``build``, whether the ``is_dir()`` guard keeps out a *file* that merely matches
``smali*``, or whether the resources flag ever reads True. An agent decides
which smali roots to patch from this list, so a dropped or bogus entry is a
missed or invalid edit.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apktool import client as apktool_client
from headless_re_mcp.backends.apktool.client import ApktoolClient


def _apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
    return path


def _decoded_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, out: Path) -> ApktoolClient:
    """A decode client whose JVM run is stubbed to a clean exit, leaving the
    already-populated ``out`` tree to drive the payload shaping."""
    (out / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
    monkeypatch.setattr(apktool_client, "_run", lambda *a, **k: ("", "", 0))
    monkeypatch.setattr(apktool_client, "_require_apk_zip", lambda p: None)
    tool = tmp_path / "apktool.bat"
    tool.write_text("@echo off\n", encoding="utf-8")
    return ApktoolClient(tool, None)


def test_multi_dex_smali_dirs_are_collected_whole_and_sorted_with_resources_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A multi-dex APK decodes to smali, smali_classes2, smali_classes3. All
    three must appear, in sorted order (created here reversed so a dropped sort
    shows), and a present res/ tree must flag has_resources True.
    """
    apk = _apk(tmp_path / "a.apk")
    out = tmp_path / "decoded"
    out.mkdir()
    for name in ("smali_classes3", "smali_classes2", "smali"):
        (out / name).mkdir()
    (out / "res").mkdir()
    client = _decoded_client(tmp_path, monkeypatch, out)

    payload = client.decode(apk, out)

    assert payload["smali_dirs"] == ["smali", "smali_classes2", "smali_classes3"]
    assert payload["has_resources"] is True


def test_a_file_matching_the_smali_glob_is_not_listed_as_a_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """apktool never writes one, but a stray file named like a smali dir must
    not slip in: the is_dir() guard is the only thing keeping smali_dirs a list
    of directories an agent can descend into.
    """
    apk = _apk(tmp_path / "a.apk")
    out = tmp_path / "decoded"
    out.mkdir()
    (out / "smali").mkdir()
    (out / "smali_classes2").write_text("i am a file, not a dir", encoding="utf-8")
    client = _decoded_client(tmp_path, monkeypatch, out)

    payload = client.decode(apk, out)

    assert payload["smali_dirs"] == ["smali"]


def test_non_smali_directories_never_leak_into_smali_dirs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """apktool also emits original/, unknown/, build/ (and res/). The smali*
    glob must keep those out of smali_dirs; with no res/ here, has_resources is
    False -- the negative that separates a resource-bearing decode from one
    stripped with -r.
    """
    apk = _apk(tmp_path / "a.apk")
    out = tmp_path / "decoded"
    out.mkdir()
    (out / "smali").mkdir()
    for name in ("original", "unknown", "build"):
        (out / name).mkdir()
    client = _decoded_client(tmp_path, monkeypatch, out)

    payload = client.decode(apk, out)

    assert payload["smali_dirs"] == ["smali"]
    assert payload["has_resources"] is False


def test_smali_dirs_are_bare_names_not_full_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each entry is the directory's name (``smali``), not its absolute path, so
    a caller joins it against decoded_dir rather than receiving a path it must
    strip. A single entry could pass either way; pin the name explicitly.
    """
    apk = _apk(tmp_path / "a.apk")
    out = tmp_path / "decoded"
    out.mkdir()
    (out / "smali").mkdir()
    client = _decoded_client(tmp_path, monkeypatch, out)

    payload = client.decode(apk, out)

    assert payload["smali_dirs"] == ["smali"]
    assert str(out) not in payload["smali_dirs"][0]
