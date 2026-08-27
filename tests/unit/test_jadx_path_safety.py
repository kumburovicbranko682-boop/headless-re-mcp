from __future__ import annotations

import os
from pathlib import Path

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
    assert _class_to_java_path("Lcom/example/Main$Inner;") == Path(
        "com/example/Main.java"
    )


def _client_over_tree(
    tmp_path: Path, relative_files: list[str], monkeypatch: pytest.MonkeyPatch
) -> tuple[JadxClient, Path]:
    """A JadxClient whose export_sources is a no-op over a pre-built tree.

    decompile runs export_sources first, then resolves the class off disk, so a
    stubbed export plus a hand-built sources/ tree exercises the resolution path
    on its own -- no real jadx, no APK needed.
    """
    out = tmp_path / "out"
    sources = out / "sources"
    for rel in relative_files:
        path = sources / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"// {rel}", encoding="utf-8")
    client = JadxClient(tmp_path / "jadx")
    monkeypatch.setattr(client, "export_sources", lambda *args, **kwargs: {})
    return client, out


def test_jadx_finds_a_class_by_simple_name_when_the_package_path_differs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """jadx may emit a class under a path that is not its dotted package.

    When the exact <package>/<Name>.java is absent but exactly one <Name>.java
    exists anywhere in the tree, decompile falls back to that one -- covering
    jadx layouts that do not mirror the requested package (obfuscated or
    repackaged apps, or a class jadx placed under a synthetic root).
    """
    client, out = _client_over_tree(tmp_path, ["repackaged/Main.java"], monkeypatch)

    result = client.decompile(tmp_path / "app.apk", out, "com.example.Main")

    assert result["class_name"] == "com.example.Main"
    assert result["source"] == "// repackaged/Main.java"
    assert result["path"].endswith("Main.java")


def test_jadx_refuses_an_ambiguous_simple_name_rather_than_guessing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two Main.java in different packages must not resolve to an arbitrary one.

    The simple-name fallback used to return whichever Main.java jadx emitted
    first, which could hand back a different class than the caller named. When
    more than one matches, decompile refuses with not_found instead of guessing:
    returning the wrong class's source is worse than returning none, and this is
    the behaviour the uniqueness check exists to guarantee.
    """
    client, out = _client_over_tree(
        tmp_path, ["a/Main.java", "b/Main.java"], monkeypatch
    )

    with pytest.raises(JadxError) as caught:
        client.decompile(tmp_path / "app.apk", out, "com.example.Main")

    assert caught.value.code == "not_found"


def test_jadx_reports_not_found_when_no_such_class_was_decompiled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A class jadx never emitted is not_found, with the path it looked for."""
    client, out = _client_over_tree(tmp_path, ["com/other/Thing.java"], monkeypatch)

    with pytest.raises(JadxError) as caught:
        client.decompile(tmp_path / "app.apk", out, "com.example.Main")

    assert caught.value.code == "not_found"
    assert caught.value.details.get("expected") == str(Path("com/example/Main.java"))


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
