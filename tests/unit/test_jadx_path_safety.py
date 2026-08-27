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


def test_jadx_rejects_an_invalid_class_name_before_decompiling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The static class-path check runs before the whole-APK decompile.

    Otherwise a malformed class_name pays for a full jadx run (or is masked as
    capability_unavailable when jadx is missing) only to be rejected afterward.
    """
    client = JadxClient(tmp_path / "jadx")

    def _must_not_run(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise AssertionError("export_sources ran for a statically invalid class_name")

    monkeypatch.setattr(client, "export_sources", _must_not_run)

    with pytest.raises(JadxError) as caught:
        client.decompile(tmp_path / "app.apk", tmp_path / "out", "com.example.\x00Main")

    assert caught.value.code == "invalid_params"


def test_jadx_simple_name_fallback_does_not_treat_a_wildcard_as_a_glob(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A class_name with glob metacharacters must not match a different class.

    When the exact source path is absent, decompile falls back to a basename
    walk. rglob reads its argument as a glob, and the JVM permits ``*`` in a
    class name, so ``com.example.Foo*`` reached rglob as ``Foo*.java`` and
    matched the lone ``Foobar.java``, returning that class's source under the
    requested name. Escaping the basename makes the walk match the literal
    filename, which does not exist, so the caller gets an honest not_found
    instead of a different class's source.
    """
    out = tmp_path / "out"
    src = out / "sources" / "com" / "example"
    src.mkdir(parents=True)
    (src / "Foobar.java").write_text("class Foobar { /* secret */ }", encoding="utf-8")
    client = JadxClient(tmp_path / "jadx")
    monkeypatch.setattr(client, "export_sources", lambda *args, **kwargs: {})

    with pytest.raises(JadxError) as caught:
        client.decompile(tmp_path / "app.apk", out, "com.example.Foo*")

    assert caught.value.code == "not_found"
    assert "secret" not in str(caught.value.details)


def test_jadx_simple_name_fallback_still_resolves_a_relocated_class(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The basename walk must still find a real class jadx emitted elsewhere.

    Escaping the rglob pattern only neutralises glob metacharacters; a genuine
    class name (no wildcards) whose file landed under a different package layout
    than its dotted name implies is still resolved by its unique basename.
    """
    out = tmp_path / "out"
    src = out / "sources" / "relocated" / "pkg"
    src.mkdir(parents=True)
    (src / "Foobar.java").write_text("class Foobar {}", encoding="utf-8")
    client = JadxClient(tmp_path / "jadx")
    monkeypatch.setattr(client, "export_sources", lambda *args, **kwargs: {})

    payload = client.decompile(tmp_path / "app.apk", out, "com.example.Foobar")

    assert payload["class_name"] == "com.example.Foobar"
    assert Path(payload["path"]).name == "Foobar.java"
    assert payload["source"] == "class Foobar {}"


def test_jadx_valid_class_name_falls_through_to_the_missing_backend(
    tmp_path: Path,
) -> None:
    """A valid class_name passes the static check and reaches the backend gate.

    The jadx path is not a real file, so a valid name degrades to
    capability_unavailable -- proving validation did not reject it (skip != pass).
    """
    client = JadxClient(tmp_path / "jadx")

    with pytest.raises(JadxError) as caught:
        client.decompile(tmp_path / "app.apk", tmp_path / "out", "com.example.Main")

    assert caught.value.code == "capability_unavailable"
