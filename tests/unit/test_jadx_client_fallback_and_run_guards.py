"""jadx fallback resolution and subprocess guard paths behave as promised.

apk.decompile resolves a class to its expected package path first, then -- for
a bare name -- jadx's ``defpackage/`` tree (where classes without a package
actually land), and only then falls back to a simple-name walk of the jadx
tree, accepting the file only when the walk is unambiguous. These lock in that
resolution contract (default-package names round-trip from apk.classes, a
unique match wins, decoys that are not regular files or cannot be resolved are
skipped, a missing tree or ambiguity is ``not_found``), the bounded listing's
edge behavior (missing root, non-file matches, the counted-files ceiling), and
``_run``'s error mapping (``capability_unavailable`` without a configured
executable, ``not_found`` for a missing APK, ``timeout`` and launch failures).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.backends.jadx import client as jadx_mod
from headless_re_mcp.backends.jadx.client import (
    JadxClient,
    JadxError,
    _capped_java_listing,
)

_RUN_BOUNDED = "headless_re_mcp.backends.jadx.client.run_bounded"


def _jadx(tmp_path: Path) -> tuple[JadxClient, Path, Path]:
    tool = tmp_path / "jadx"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    out = tmp_path / "out"
    return JadxClient(tool), apk, out


def _writes(out: Path, *rel_files: str) -> Callable[..., Completed]:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        out.mkdir(parents=True, exist_ok=True)
        for rel in rel_files:
            target = out / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"class {target.stem} {{}}", encoding="utf-8")
        return Completed(0, b"", b"")

    return fake_run


def test_listing_a_missing_root_is_empty(tmp_path: Path) -> None:
    names, total, has_more = _capped_java_listing(tmp_path / "absent", cap=10)

    assert names == []
    assert total == 0
    assert has_more is False


def test_listing_skips_a_directory_named_like_a_java_file(tmp_path: Path) -> None:
    (tmp_path / "Fake.java").mkdir()
    (tmp_path / "Real.java").write_text("class Real {}", encoding="utf-8")

    names, total, has_more = _capped_java_listing(tmp_path, cap=10)

    assert names == ["Real.java"]
    assert total == 1
    assert has_more is False


def test_listing_stops_counting_at_the_file_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jadx_mod, "_MAX_COUNTED_FILES", 2)
    for index in range(3):
        (tmp_path / f"C{index}.java").write_text("class C {}", encoding="utf-8")

    names, total, has_more = _capped_java_listing(tmp_path, cap=10)

    assert total == 2
    assert len(names) == 2
    assert has_more is True


def test_decompile_rejects_a_blank_class_name(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)

    with pytest.raises(JadxError) as caught:
        client.decompile(apk, out, "   ")

    assert caught.value.code == "invalid_params"


def test_decompile_falls_back_to_a_unique_simple_name_match(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)
    fake_run = _writes(out, "sources/pkg/Main.java")

    def fake_with_decoy(cmd: list[str], **kwargs: Any) -> Completed:
        completed = fake_run(cmd, **kwargs)
        # A directory named like the class file must not count as a match.
        (out / "sources" / "decoy" / "Main.java").mkdir(parents=True)
        return completed

    with patch(_RUN_BOUNDED, fake_with_decoy):
        payload = client.decompile(apk, out, "com.example.Main")

    assert payload["source"] == "class Main {}"
    assert payload["path"] == str(out / "sources" / "pkg" / "Main.java")


def test_decompile_skips_a_match_that_cannot_be_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, apk, out = _jadx(tmp_path)
    real_resolve = Path.resolve

    def failing_resolve(self: Path, *args: Any, **kwargs: Any) -> Path:
        if self.name == "Main.java" and "decoy" in self.parts:
            raise OSError("resolve failed")
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", failing_resolve)

    with (
        patch(_RUN_BOUNDED, _writes(out, "sources/decoy/Main.java")),
        pytest.raises(JadxError) as caught,
    ):
        client.decompile(apk, out, "com.example.Main")

    assert caught.value.code == "not_found"
    assert caught.value.details["class_name"] == "com.example.Main"


def test_a_default_package_class_resolves_into_the_defpackage_tree(tmp_path: Path) -> None:
    """The names apk.classes reports for default-package classes round-trip.

    Measured with real jadx 1.5.1 on a jar holding the classic obfuscation
    homonym pair (default-package ``a`` plus ``a.a``): jadx wrote
    ``sources/defpackage/a.java`` and ``sources/a/a.java``, and
    ``decompile("a")`` / ``decompile("La;")`` -- the exact names ``apk.classes``
    hands back -- both answered not_found: the exact probe looked at the
    sources root and the simple-name walk saw two ``a.java`` files. A bare
    name must resolve into jadx's ``defpackage/`` tree, deterministically,
    and never be shadowed by the homonym.
    """
    client, apk, out = _jadx(tmp_path)
    fake_run = _writes(out, "sources/defpackage/a.java", "sources/a/a.java")

    for name in ("a", "La;"):
        with patch(_RUN_BOUNDED, fake_run):
            payload = client.decompile(apk, out, name)
        assert payload["path"] == str(out / "sources" / "defpackage" / "a.java"), name

    # The qualified homonym keeps resolving by its exact package path.
    with patch(_RUN_BOUNDED, fake_run):
        qualified = client.decompile(apk, out, "a.a")
    assert qualified["path"] == str(out / "sources" / "a" / "a.java")


def test_a_sources_root_file_wins_over_the_defpackage_candidate(tmp_path: Path) -> None:
    # If some jadx build ever emits a packageless class at the sources root,
    # the exact probe must keep priority; defpackage/ is only the second try.
    client, apk, out = _jadx(tmp_path)
    fake_run = _writes(out, "sources/a.java", "sources/defpackage/a.java")

    with patch(_RUN_BOUNDED, fake_run):
        payload = client.decompile(apk, out, "a")

    assert payload["path"] == str(out / "sources" / "a.java")


def test_a_bare_name_without_a_defpackage_hit_still_uses_the_unique_fallback(
    tmp_path: Path,
) -> None:
    client, apk, out = _jadx(tmp_path)
    fake_run = _writes(out, "sources/pkg/Solo.java")

    with patch(_RUN_BOUNDED, fake_run):
        payload = client.decompile(apk, out, "Solo")

    assert payload["path"] == str(out / "sources" / "pkg" / "Solo.java")


def _writes_content(out: Path, files: dict[str, str]) -> Callable[..., Completed]:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        out.mkdir(parents=True, exist_ok=True)
        for rel, content in files.items():
            target = out / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return Completed(0, b"", b"")

    return fake_run


def test_a_class_jadx_renamed_is_found_through_its_renamed_from_comment(
    tmp_path: Path,
) -> None:
    """Classes with names jadx's filesystem rules refuse still round-trip.

    Measured with jadx 1.5.1: a default-package class named ``类`` was written
    as ``sources/defpackage/C0000.java`` with the original spelling only in a
    leading ``/* renamed from: 类, reason: ... */`` comment (simple name for
    default-package classes), and a packaged ``p.类2`` as ``sources/p/C2.java``
    with the fully qualified ``renamed from: p.类2``. The exact probe, the
    defpackage probe and the simple-name walk all miss such files, so the
    names apk.classes reports answered not_found while the sources sat on
    disk. The boundary matters too: asking for ``类`` must not match the file
    renamed from ``类2``.
    """
    client, apk, out = _jadx(tmp_path)
    fake_run = _writes_content(
        out,
        {
            "sources/defpackage/C0000.java": (
                "package defpackage;\n\n"
                "/* renamed from: 类, reason: contains not printable characters */\n"
                "public class C0000 {\n}\n"
            ),
            "sources/defpackage/C0001.java": (
                "package defpackage;\n\n"
                "/* renamed from: 类2, reason: contains not printable characters */\n"
                "public class C0001 {\n}\n"
            ),
            "sources/p/C2.java": (
                "package p;\n\n"
                "/* renamed from: p.类2, reason: invalid class name */\n"
                "public class C2 {\n}\n"
            ),
        },
    )

    for name, expected in (
        ("类", out / "sources" / "defpackage" / "C0000.java"),
        ("L类;", out / "sources" / "defpackage" / "C0000.java"),
        ("类2", out / "sources" / "defpackage" / "C0001.java"),
        ("p.类2", out / "sources" / "p" / "C2.java"),
        ("Lp/类2;", out / "sources" / "p" / "C2.java"),
    ):
        with patch(_RUN_BOUNDED, fake_run):
            payload = client.decompile(apk, out, name)
        assert payload["path"] == str(expected), name


def test_the_rename_scan_stays_inside_its_package_directory(tmp_path: Path) -> None:
    # p.类2's comment lives under sources/p/; asking for the same class under
    # another package must not be redirected across packages.
    client, apk, out = _jadx(tmp_path)
    fake_run = _writes_content(
        out,
        {
            "sources/p/C2.java": (
                "package p;\n\n"
                "/* renamed from: p.类2, reason: invalid class name */\n"
                "public class C2 {\n}\n"
            ),
        },
    )

    with patch(_RUN_BOUNDED, fake_run), pytest.raises(JadxError) as caught:
        client.decompile(apk, out, "q.类2")

    assert caught.value.code == "not_found"


def test_the_rename_scan_respects_its_file_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jadx_mod, "_MAX_RENAME_SCAN_FILES", 1)
    client, apk, out = _jadx(tmp_path)
    # Sorted scan order reads A.java first and stops at the ceiling before
    # reaching Z.java, where the wanted comment lives.
    fake_run = _writes_content(
        out,
        {
            "sources/defpackage/A.java": "package defpackage;\npublic class A {\n}\n",
            "sources/defpackage/Z.java": (
                "package defpackage;\n\n"
                "/* renamed from: 类, reason: contains not printable characters */\n"
                "public class Z {\n}\n"
            ),
        },
    )

    with patch(_RUN_BOUNDED, fake_run), pytest.raises(JadxError) as caught:
        client.decompile(apk, out, "类")

    assert caught.value.code == "not_found"


def test_a_bare_name_that_matches_nothing_stays_not_found(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)
    fake_run = _writes(out, "sources/x/b.java", "sources/y/b.java")

    with patch(_RUN_BOUNDED, fake_run), pytest.raises(JadxError) as caught:
        client.decompile(apk, out, "b")

    assert caught.value.code == "not_found"


def test_decompile_is_not_found_when_the_name_is_ambiguous(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)
    fake_run = _writes(out, "sources/a/Main.java", "sources/b/Main.java")

    with patch(_RUN_BOUNDED, fake_run), pytest.raises(JadxError) as caught:
        client.decompile(apk, out, "com.example.Main")

    assert caught.value.code == "not_found"
    assert caught.value.details["expected"] == str(Path("com", "example", "Main.java"))


def test_decompile_is_not_found_when_jadx_wrote_no_sources_tree(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)
    # A stray file outside sources/ keeps _run happy but leaves no tree to walk.
    fake_run = _writes(out, "Stray.java")

    with patch(_RUN_BOUNDED, fake_run), pytest.raises(JadxError) as caught:
        client.decompile(apk, out, "com.example.Main")

    assert caught.value.code == "not_found"


def test_decompile_maps_an_unreadable_source_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, apk, out = _jadx(tmp_path)
    real_open = Path.open

    def failing_open(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if self.suffix == ".java" and "b" in mode:
            raise OSError("read failed")
        return real_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing_open)

    with (
        patch(_RUN_BOUNDED, _writes(out, "sources/com/example/Main.java")),
        pytest.raises(JadxError) as caught,
    ):
        client.decompile(apk, out, "com.example.Main")

    assert caught.value.code == "backend_error"
    assert "failed to read source" in caught.value.message


def test_run_without_a_configured_executable_is_capability_unavailable(
    tmp_path: Path,
) -> None:
    client = JadxClient(None)

    with pytest.raises(JadxError) as caught:
        client.export_sources(tmp_path / "app.apk", tmp_path / "out")

    assert caught.value.code == "capability_unavailable"


def test_run_with_a_missing_apk_is_not_found(tmp_path: Path) -> None:
    client, _, out = _jadx(tmp_path)

    with pytest.raises(JadxError) as caught:
        client.export_sources(tmp_path / "missing.apk", out)

    assert caught.value.code == "not_found"
    assert caught.value.details["path"] == str(tmp_path / "missing.apk")


def test_run_maps_a_timed_out_jadx_to_timeout(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        raise TimedOut(5.0, killed=[123])

    with patch(_RUN_BOUNDED, fake_run), pytest.raises(JadxError) as caught:
        client.export_sources(apk, out, timeout=5.0)

    assert caught.value.code == "timeout"
    assert caught.value.details["killed_pids"] == [123]


def test_run_maps_a_launch_failure_to_backend_error(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        raise OSError("exec format error")

    with patch(_RUN_BOUNDED, fake_run), pytest.raises(JadxError) as caught:
        client.export_sources(apk, out)

    assert caught.value.code == "backend_error"
    assert "failed to launch jadx" in caught.value.message
