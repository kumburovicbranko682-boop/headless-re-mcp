from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jadx.client import (
    JadxClient,
    JadxError,
    _class_to_java_path,
)


@pytest.mark.parametrize(
    "class_name",
    [
        "../../outside",
        "com..outside.Main",
        r"C:\outside",
        "com.example.\x00Main",
        # An absolute path: the leading slash becomes an empty leading segment.
        "/etc/passwd",
        # Leading / trailing dots leave an empty segment on either end.
        ".leadingdot",
        "trailingdot.",
        # Bare relative markers and empties never map to a class file.
        "..",
        ".",
        "",
        "   ",
        # A name that is only an inner-class suffix strips to nothing.
        "$Inner",
    ],
)
def test_jadx_rejects_class_names_that_are_not_relative_java_paths(
    class_name: str,
) -> None:
    with pytest.raises(JadxError) as caught:
        _class_to_java_path(class_name)

    assert caught.value.code == "invalid_params"


def test_jadx_keeps_valid_dotted_and_smali_class_names() -> None:
    assert _class_to_java_path("com.example.Main") == Path("com/example/Main.java")
    assert _class_to_java_path("Lcom/example/Main$Inner;") == Path("com/example/Main.java")
    # A single, unqualified class name is a bare file at the root.
    assert _class_to_java_path("Main") == Path("Main.java")
    # Slash-separated (non-smali) is accepted the same as dotted.
    assert _class_to_java_path("com/example/Main") == Path("com/example/Main.java")
    # A dotted inner class folds into its outer file, like the smali form.
    assert _class_to_java_path("com.example.Main$Inner") == Path("com/example/Main.java")
    # Smali without an inner suffix drops only the L...; wrapper.
    assert _class_to_java_path("Lcom/example/Main;") == Path("com/example/Main.java")
    # Surrounding whitespace is stripped before the path is built.
    assert _class_to_java_path("  com.example.Main  ") == Path("com/example/Main.java")


def test_jadx_rejects_a_class_name_whose_path_would_exceed_the_filesystem() -> None:
    """An over-length class_name is refused as invalid_params, not left to crash.

    decompile() resolves the class_name to ``out_dir/sources/<pkg>/<Class>.java``
    and then calls ``candidate.is_file()``. If a segment exceeds the filesystem's
    NAME_MAX (255 bytes on ext4/most POSIX) that stat raises a raw
    ``OSError(ENAMETOOLONG)`` -- and unlike ENOENT, pathlib does *not* swallow it
    (confirmed: ``is_file`` re-raises errno 36) -- so the tool would surface an
    uncaught OSError on a caller's bad argument instead of the clean invalid_params
    it should. The bound now lives in the pure resolver, so it fails fast before
    the whole-APK export even runs.

    A single 251-char terminal segment is enough: the ``.java`` suffix pushes the
    real filename component to 256 bytes, one past NAME_MAX. Deeply nested short
    segments trip the whole-path ceiling instead, so both arms are exercised.
    """
    long_leaf = "A" * 251
    with pytest.raises(JadxError) as leaf_caught:
        _class_to_java_path(f"com.example.{long_leaf}")
    assert leaf_caught.value.code == "invalid_params"
    assert "segment" in leaf_caught.value.message

    long_segment = "com.example." + ("b" * 300) + ".Main"
    with pytest.raises(JadxError) as seg_caught:
        _class_to_java_path(long_segment)
    assert seg_caught.value.code == "invalid_params"

    # Many short segments stay under NAME_MAX each but blow the 1024-byte path cap.
    deep = ".".join(["seg"] * 400 + ["Main"])
    with pytest.raises(JadxError) as path_caught:
        _class_to_java_path(deep)
    assert path_caught.value.code == "invalid_params"
    assert "too long" in path_caught.value.message


def test_jadx_keeps_class_names_right_up_to_the_filesystem_limit() -> None:
    """Non-vacuity: the bound rejects only what a filesystem could not name.

    A 250-char leaf becomes a 255-byte ``<name>.java`` component -- exactly
    NAME_MAX, the largest a filesystem accepts -- and a 255-byte package segment
    is the largest directory name, so both must still be accepted. jadx could in
    principle emit these, so rejecting them would drop a reachable class; the
    guard must bite one byte later, not here.
    """
    leaf = "C" * 250
    assert _class_to_java_path(f"pkg.{leaf}") == Path("pkg") / f"{leaf}.java"
    segment = "d" * 255
    assert _class_to_java_path(f"{segment}.Main") == Path(segment) / "Main.java"


def test_jadx_validates_class_name_before_the_whole_apk_decompile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A malformed class_name must fail before export_sources launches jadx.

    decompile() used to run the whole-APK export first and validate the
    class_name via _class_to_java_path after -- so a class_name carrying a
    backslash, a colon, a NUL, or a .. / empty path segment paid for a full jadx
    run (up to the 1800s timeout, writing an entire source tree) before being
    rejected, and on a host without jadx was masked by export_sources'
    capability_unavailable rather than surfacing the invalid_params it was. The
    resolution now runs first: a bad name is refused up front and the expensive
    export is never reached, proven by a spy that must stay uncalled for every
    malformed name and fire exactly once for a well-formed one.
    """
    calls: list[tuple[Any, ...]] = []

    def _recording_export(*args: Any, **kwargs: Any) -> dict[str, Any]:
        calls.append(args)
        return {}

    client = JadxClient(tmp_path / "jadx")
    monkeypatch.setattr(client, "export_sources", _recording_export)

    for bad in (
        "com.example.\x00Main",
        r"C:\outside",
        "../../outside",
        "com..outside",
        # An over-length segment resolves to a path the filesystem cannot name;
        # caught here it fails fast, otherwise it is only rejected deep inside
        # decompile after the whole-APK export -- as a misleading not_found, or a
        # raw ENAMETOOLONG crash once a real export has written the sources tree
        # (pinned by the sibling test below).
        "com.example." + ("z" * 300),
    ):
        with pytest.raises(JadxError) as caught:
            client.decompile(tmp_path / "app.apk", tmp_path / "out", bad)
        assert caught.value.code == "invalid_params"
    assert calls == [], "export_sources ran before the class_name was validated"

    # A well-formed name does reach the export (the spy stands in for it) and
    # then fails downstream because the spy wrote no tree -- proof the reorder
    # did not simply short-circuit every call.
    with pytest.raises(JadxError):
        client.decompile(tmp_path / "app.apk", tmp_path / "out", "com.example.Main")
    assert len(calls) == 1, "a valid class name must still reach export_sources exactly once"


def test_jadx_over_length_class_name_does_not_crash_after_a_real_export(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With a sources tree on disk, an over-length name is a clean error, not a crash.

    The before-export test proves the length check fires early; this proves what
    it prevents. Here the stub export actually creates ``sources/``, so decompile
    walks past the parent-exists check and reaches ``candidate.is_file()`` on a
    path whose final component is past NAME_MAX. That stat raises
    ``OSError(ENAMETOOLONG)``, which pathlib re-raises rather than swallowing the
    way it does ENOENT -- so without the resolver's bound the tool would surface an
    uncaught OSError (a 500-shaped crash) on a caller's bad argument. The guard
    turns it into the invalid_params it always was.
    """

    def _export_writing_a_tree(apk: Path, out: Path, *, timeout: float) -> dict[str, Any]:
        (out / "sources").mkdir(parents=True, exist_ok=True)
        return {}

    client = JadxClient(tmp_path / "jadx")
    monkeypatch.setattr(client, "export_sources", _export_writing_a_tree)

    with pytest.raises(JadxError) as caught:
        client.decompile(tmp_path / "app.apk", tmp_path / "out", "com.example." + ("z" * 300))
    assert caught.value.code == "invalid_params"


@pytest.mark.skipif(os.name == "nt", reason="creating test symlinks needs Windows privileges")
def test_jadx_does_not_read_a_source_symlink_outside_its_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outside = tmp_path / "private.java"
    outside.write_text("private source", encoding="utf-8")
    out = tmp_path / "out"
    candidate = out / "sources" / "com" / "example" / "Main.java"
    candidate.parent.mkdir(parents=True)
    candidate.symlink_to(outside)
    client = JadxClient(tmp_path / "jadx")
    monkeypatch.setattr(client, "export_sources", lambda *args, **kwargs: {})

    with pytest.raises(JadxError) as caught:
        client.decompile(tmp_path / "app.apk", out, "com.example.Main")

    assert caught.value.code == "invalid_params"
    assert "private source" not in str(caught.value.details)


@pytest.mark.skipif(os.name == "nt", reason="creating test symlinks needs Windows privileges")
def test_jadx_rejects_a_sources_directory_redirected_outside_the_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    (out / "sources").symlink_to(outside, target_is_directory=True)
    client = JadxClient(tmp_path / "jadx")
    monkeypatch.setattr(client, "export_sources", lambda *args, **kwargs: {})

    with pytest.raises(JadxError) as caught:
        client.decompile(tmp_path / "app.apk", out, "com.example.Main")

    assert caught.value.code == "backend_error"
