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

    for bad in ("com.example.\x00Main", r"C:\outside", "../../outside", "com..outside"):
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
