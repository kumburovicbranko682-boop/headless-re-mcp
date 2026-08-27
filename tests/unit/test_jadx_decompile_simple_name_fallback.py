"""``apk.decompile``'s simple-name recovery returns the caller's class or nothing.

``JadxClient.decompile`` decompiles the whole APK, then reads back the one class
the caller named. It first looks at the path derived from the class name --
``com.example.Main`` -> ``sources/com/example/Main.java``. jadx does not always
emit a class at that package-derived path (a ``SourceFile`` attribute, an
obfuscated remap, or a default-package class can land it elsewhere), so when the
derived path is not a file ``decompile`` falls back to walking the tree for a
file with the class's simple name:

    matches = [p for p in sources.rglob(candidate.name) if <inside sources & file>]
    if len(matches) == 1:
        match = matches[0]
    if match is None:
        raise JadxError("not_found", ...)

The ``len(matches) == 1`` gate is the load-bearing part, and its comment records
the regression it fixed: a bare simple-name walk "used to return the first
Main.java in the tree, which is whoever jadx happened to emit first -- not
necessarily the class the caller named." So the contract has three arms once the
exact path misses: exactly one same-named file anywhere -> return it; zero ->
``not_found``; two or more -> ``not_found`` as well, because guessing would hand
back the wrong class's source under the caller's requested name.

Every existing jadx test writes the class at its exact derived path
(``_writes_one_class`` -> ``sources/com/example/Main.java`` for
``com.example.Main``) or fakes ``decompile`` outright (``_TrackingJadx``), so
``candidate.is_file()`` is always true and this entire fallback -- the recovery,
the ambiguity refusal, and the zero-match ``not_found`` -- is never exercised.
Drop the fallback and the recovery test breaks; loosen ``== 1`` to "first match
wins" and the ambiguity test breaks; neither would disturb the existing suite.
These pin all three arms directly, plus that the exact path still wins over a
same-named decoy elsewhere in the tree.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jadx.client import JadxClient, JadxError


def _client_with_tree(
    tmp_path: Path,
    rel_paths: list[str],
    *,
    export_result: dict[str, Any] | None = None,
) -> tuple[JadxClient, Path, Path]:
    """A JadxClient whose ``export_sources`` is stubbed and whose tree we lay out.

    ``decompile`` calls ``export_sources`` (the real jadx run) first, then reads
    the tree from disk. Stubbing ``export_sources`` to a no-op and pre-writing
    the ``sources`` tree lets us drive the pure path-resolution logic without a
    jadx binary, exactly the way ``test_jadx_path_safety`` does. Each written
    file carries its own relative path in the body so a test can prove *which*
    class it got back, not merely that it got source.
    """
    out = tmp_path / "out"
    sources = out / "sources"
    for rel in rel_paths:
        path = sources / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"// {rel}\nclass Sample {{}}", encoding="utf-8")
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    client = JadxClient(tmp_path / "jadx")
    result = dict(export_result or {})
    client.export_sources = lambda *args, **kwargs: dict(result)  # type: ignore[method-assign]
    return client, apk, out


def test_decompile_recovers_a_unique_simple_name_match_off_the_derived_path(
    tmp_path: Path,
) -> None:
    """No file at the package path, one Main.java elsewhere -> return that one.

    This is jadx emitting the class somewhere other than its package-derived
    directory. The fallback finds the single same-named file and returns *its*
    source (the body proves it), so the recovery is not dead code. The whole-run
    verdict from ``export_sources`` must still ride along on this recovery path
    just as it does on an exact hit.
    """
    client, apk, out = _client_with_tree(
        tmp_path,
        ["remapped/Main.java"],
        export_result={"exit_code": 1, "tool_failed": True, "stderr": "partial"},
    )

    payload = client.decompile(apk, out, "com.example.Main")

    assert payload["class_name"] == "com.example.Main"
    assert payload["source"].splitlines()[0] == "// remapped/Main.java"
    assert Path(payload["path"]).name == "Main.java"
    # The recovery path must not swallow the run's partial-failure verdict.
    assert payload["exit_code"] == 1
    assert payload["tool_failed"] is True
    assert payload["stderr"] == "partial"


def test_decompile_prefers_the_exact_derived_path_over_a_same_named_decoy(
    tmp_path: Path,
) -> None:
    """When the package path *does* exist, the fallback is not consulted.

    A decoy ``Main.java`` sits elsewhere in the tree; the class must come from
    the derived ``com/example/Main.java``, never the decoy. This pins that the
    exact hit short-circuits before the simple-name walk, so the walk can never
    override a correctly-placed class.
    """
    client, apk, out = _client_with_tree(
        tmp_path, ["com/example/Main.java", "decoy/Main.java"]
    )

    payload = client.decompile(apk, out, "com.example.Main")

    assert payload["source"].splitlines()[0] == "// com/example/Main.java"
    assert Path(payload["path"]).parent.name == "example"


def test_decompile_refuses_to_guess_when_the_simple_name_is_ambiguous(
    tmp_path: Path,
) -> None:
    """Two same-named files, neither at the derived path -> not_found, no guess.

    This is the regression the ``len(matches) == 1`` gate fixed: returning "the
    first Main.java in the tree" would hand back some *other* package's class
    under the name the caller asked for. With two candidates and no exact hit
    the only safe answer is ``not_found`` -- returning either would be wrong.
    """
    client, apk, out = _client_with_tree(tmp_path, ["a/Main.java", "b/Main.java"])

    with pytest.raises(JadxError) as caught:
        client.decompile(apk, out, "com.example.Main")

    assert caught.value.code == "not_found"
    assert caught.value.details["expected"] == "com/example/Main.java"


def test_decompile_reports_not_found_when_no_same_named_file_exists(
    tmp_path: Path,
) -> None:
    """No exact path and no simple-name match anywhere -> not_found with the path.

    The zero-match arm of the fallback. The reply names the expected derived
    path so a caller can see which class jadx never emitted, rather than a bare
    failure.
    """
    client, apk, out = _client_with_tree(tmp_path, ["other/Helper.java"])

    with pytest.raises(JadxError) as caught:
        client.decompile(apk, out, "com.example.Main")

    assert caught.value.code == "not_found"
    assert caught.value.details["class_name"] == "com.example.Main"
    assert caught.value.details["expected"] == "com/example/Main.java"
