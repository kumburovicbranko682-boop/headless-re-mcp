"""jadx's one-shot guards: honest degradation and the bounded source walk.

The path-safety suite drives class resolution over a stubbed export; these cover
the ``_run`` preconditions that decide whether jadx is even launched -- the
contract the module docstring promises ("when either is missing the tool
degrades to capability_unavailable rather than blocking readiness") -- and the
``_capped_java_listing`` walk that keeps an obfuscated APK's five-figure class
tree from building an unbounded reply or counting forever.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.jadx.client as jadx_client
from headless_re_mcp.backends.jadx.client import JadxClient, JadxError, _capped_java_listing


def _apk(tmp_path: Path) -> Path:
    path = tmp_path / "app.apk"
    path.write_bytes(b"PK\x03\x04")
    return path


def _configured_client(tmp_path: Path) -> JadxClient:
    """A client whose executable exists on disk, so ``available`` is True.

    The apk/launch guards live past the availability check, so reaching them
    needs a jadx that looks configured -- a real file is enough; it is never run
    because run_bounded is stubbed or the guard fires first.
    """
    executable = tmp_path / "jadx"
    executable.write_bytes(b"")
    return JadxClient(executable)


def test_export_sources_without_a_configured_jadx_is_capability_unavailable(
    tmp_path: Path,
) -> None:
    """No jadx on disk degrades, rather than launching nothing or erroring hard.

    An unconfigured backend must answer capability_unavailable -- the readiness
    contract that lets the rest of the server come up without jadx -- not
    not_found (which would read as a bad apk) or an internal_error incident.
    """
    client = JadxClient(None)
    assert client.available is False
    with pytest.raises(JadxError) as caught:
        client.export_sources(_apk(tmp_path), tmp_path / "out")
    assert caught.value.code == "capability_unavailable"


def test_a_dangling_configured_jadx_names_the_bad_path(tmp_path: Path) -> None:
    """A configured path that is not a file is a settings typo, not an absent tool.

    Both states degrade to capability_unavailable, but they used to share one
    bare "jadx is not configured" message, so HEADLESS_RE_JADX pointing at a
    missing file read exactly like jadx never being installed. The dangling arm
    now carries the path, so the operator fixes the setting instead of
    reinstalling the tool -- the same split webcrack got and the doctor's
    dangling-config MISSING report names.
    """
    dangling = tmp_path / "vendor" / "jadx"  # never created
    client = JadxClient(dangling)
    assert client.available is False
    with pytest.raises(JadxError) as caught:
        client.export_sources(_apk(tmp_path), tmp_path / "out")
    assert caught.value.code == "capability_unavailable"
    assert caught.value.details["executable"] == str(dangling)


def test_export_sources_reports_a_missing_apk_as_not_found(tmp_path: Path) -> None:
    """A configured jadx pointed at a nonexistent apk is not_found, not a launch.

    The guard fires before run_bounded, so the caller learns the input is
    missing rather than jadx being spawned on a path that is not there. The
    reply carries the path it looked for.
    """
    client = _configured_client(tmp_path)
    assert client.available is True
    missing = tmp_path / "nope.apk"
    with pytest.raises(JadxError) as caught:
        client.export_sources(missing, tmp_path / "out")
    assert caught.value.code == "not_found"
    assert caught.value.details.get("path") == str(missing)


def test_export_sources_maps_a_launch_oserror_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A jadx that cannot be spawned is a backend problem, not an internal fault.

    An OSError from run_bounded -- the JRE gone, the launcher not executable,
    the file vanished between the availability check and spawn -- would surface
    as an internal_error incident uncaught. jadx maps it to backend_error naming
    the launch, matching the Ghidra/apktool adapters.
    """
    client = _configured_client(tmp_path)

    def boom(cmd: list[str], **kwargs: Any) -> Any:
        del cmd, kwargs
        raise OSError("jre missing")

    monkeypatch.setattr(jadx_client, "run_bounded", boom)
    with pytest.raises(JadxError) as caught:
        client.export_sources(_apk(tmp_path), tmp_path / "out")
    assert caught.value.code == "backend_error"
    assert "failed to launch jadx" in caught.value.message


def test_decompile_requires_a_class_name(tmp_path: Path) -> None:
    """An empty class_name is refused before the whole APK is decompiled.

    decompile validates the name first; a blank one is a caller error
    (invalid_params), not a not_found after an expensive export -- and it must
    not fall through to resolve an empty path against the sources tree.
    """
    client = _configured_client(tmp_path)
    with pytest.raises(JadxError) as caught:
        client.decompile(_apk(tmp_path), tmp_path / "out", "   ")
    assert caught.value.code == "invalid_params"


def test_capped_java_listing_on_a_missing_root_is_empty(tmp_path: Path) -> None:
    """A tree that was never written lists nothing rather than raising.

    export_sources summarises the output even when jadx wrote nothing (a hard
    failure raises elsewhere), so the walk over a missing directory must answer
    empty, not blow up on rglob against a path that is not there.
    """
    assert _capped_java_listing(tmp_path / "absent", cap=10) == ([], 0, False)


def test_capped_java_listing_skips_a_directory_that_matches_the_glob(
    tmp_path: Path,
) -> None:
    """rglob('*.java') also matches directories; only real files are counted.

    A decompiled tree can contain a directory whose name ends in .java (jadx
    resource layouts do this); counting it as a source would inflate the count
    and list a path that cannot be read. The is_file gate skips it.
    """
    (tmp_path / "Real.java").write_text("// real", encoding="utf-8")
    (tmp_path / "NotASource.java").mkdir()
    names, total, has_more = _capped_java_listing(tmp_path, cap=10)
    assert names == ["Real.java"]
    assert total == 1
    assert has_more is False


def test_capped_java_listing_stops_at_the_hard_count_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Past the hard count cap the walk stops and says the tree was larger.

    An obfuscated APK can decompile to far more classes than anyone will read;
    the walk stops counting at _MAX_COUNTED_FILES and reports has_more so the
    reply stays bounded instead of iterating a five-figure tree to exhaustion.
    Driven with a tiny cap so the bound itself is what is exercised.
    """
    for index in range(5):
        (tmp_path / f"C{index}.java").write_text("// x", encoding="utf-8")
    monkeypatch.setattr(jadx_client, "_MAX_COUNTED_FILES", 2)
    names, total, has_more = _capped_java_listing(tmp_path, cap=10)
    assert has_more is True
    # The walk broke at the cap rather than counting every file on disk.
    assert total == 2
    assert len(names) == 2
