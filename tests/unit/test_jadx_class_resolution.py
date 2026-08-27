"""How jadx.decompile locates one class inside the decompiled source tree.

decompile() first looks for the class at the exact path its name maps to
(``com.example.Main`` -> ``sources/com/example/Main.java``). When jadx emitted
the file somewhere else -- a different package root, a flattened layout -- it
falls back to a simple-name walk. That fallback carries two contracts worth
pinning, because getting either wrong hands the agent the wrong source:

* a **unique** basename match is accepted (and a directory that happens to share
  the name is skipped, not read as a file), and
* an **ambiguous** match (two classes with the same simple name) is refused with
  ``not_found`` rather than guessing whichever jadx happened to emit first.

The whole-APK export is stubbed out (no real jadx), so these exercise only the
in-tree resolution -- the layer that turns a class name into a file to read.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jadx.client import JadxClient, JadxError


def _client_with_stubbed_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> JadxClient:
    client = JadxClient(tmp_path / "jadx")
    monkeypatch.setattr(client, "export_sources", lambda *args, **kwargs: {})
    return client


def test_decompile_refuses_a_blank_class_name_before_exporting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A class_name that is only whitespace is refused up front as invalid_params
    and never launches the (whole-APK) export -- there is nothing to resolve."""
    calls: list[Any] = []

    client = JadxClient(tmp_path / "jadx")
    monkeypatch.setattr(
        client, "export_sources", lambda *a, **k: calls.append(a) or {}
    )

    with pytest.raises(JadxError) as caught:
        client.decompile(tmp_path / "app.apk", tmp_path / "out", "   ")

    assert caught.value.code == "invalid_params"
    assert "class_name is required" in caught.value.message
    assert calls == [], "a blank class_name must fail before export_sources runs"


def test_decompile_accepts_a_unique_simple_name_match_elsewhere(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exact package path is absent, but exactly one Main.java lives in the
    tree: the fallback returns it. A directory sharing the name is skipped, not
    mistaken for the source file."""
    out = tmp_path / "out"
    sources = out / "sources"
    # The class the caller named would map to sources/com/example/Main.java,
    # which we deliberately do not create.
    relocated = sources / "relocated" / "Main.java"
    relocated.parent.mkdir(parents=True)
    relocated.write_text("class Main {}\n", encoding="utf-8")
    # A directory that happens to be named Main.java must be skipped (is_file
    # is False), leaving the real file as the single match.
    (sources / "pkg" / "Main.java").mkdir(parents=True)

    client = _client_with_stubbed_export(tmp_path, monkeypatch)
    payload = client.decompile(tmp_path / "app.apk", out, "com.example.Main")

    assert payload["class_name"] == "com.example.Main"
    assert payload["source"] == "class Main {}\n"
    assert payload["truncated"] is False
    assert Path(payload["path"]) == relocated.resolve()


def test_decompile_refuses_to_guess_between_two_same_named_classes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two Main.java files and no exact-path match: the fallback must not return
    whichever it walked into first. It fails closed with not_found so the caller
    disambiguates by full name rather than silently reading the wrong class."""
    out = tmp_path / "out"
    sources = out / "sources"
    first = sources / "a" / "Main.java"
    second = sources / "b" / "Main.java"
    for path, body in ((first, "class A {}\n"), (second, "class B {}\n")):
        path.parent.mkdir(parents=True)
        path.write_text(body, encoding="utf-8")

    client = _client_with_stubbed_export(tmp_path, monkeypatch)
    with pytest.raises(JadxError) as caught:
        client.decompile(tmp_path / "app.apk", out, "com.example.Main")

    assert caught.value.code == "not_found"
    assert caught.value.details.get("class_name") == "com.example.Main"
    assert caught.value.details.get("expected") == str(Path("com/example/Main.java"))
