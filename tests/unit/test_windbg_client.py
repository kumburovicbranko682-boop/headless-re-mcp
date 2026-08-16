from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.windbg.client as windbg_module
from headless_re_mcp.backends.windbg.client import WindbgClient, WindbgError


def _store_cdb(tmp_path: Path) -> Path:
    path = tmp_path / "WindowsApps" / "Microsoft.WinDbg_1.0_x64__abc" / "amd64" / "cdb.exe"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"MZ")
    return path


def test_store_package_cdb_is_reported_unavailable(tmp_path: Path) -> None:
    """Store package paths stat fine but CreateProcess denies them."""
    client = WindbgClient(_store_cdb(tmp_path))

    assert client.available is False


def test_store_package_cdb_raises_actionable_error(tmp_path: Path) -> None:
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")
    client = WindbgClient(_store_cdb(tmp_path))

    with pytest.raises(WindbgError) as exc:
        client.modules(dump)

    assert exc.value.code == "capability_unavailable"
    assert "HEADLESS_RE_CDB" in exc.value.message


def test_a_dump_analysis_cut_at_the_cap_says_it_was_cut(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """cdb prints the whole session, and the analytical answer is inside it.

    A listing that stopped at the cap reads exactly like one that ended, so a
    caller working out where a stack or a module list finishes would take the
    buffer boundary for the answer. Every other backend in this tree already
    flags its own truncation.
    """
    import subprocess

    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")
    monkeypatch.setattr(windbg_module, "_MAX_OUTPUT", 64)

    def huge(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"A" * 500, stderr=b"")

    monkeypatch.setattr(windbg_module, "run_bounded", huge)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)

    payload = WindbgClient(cdb).modules(dump)

    assert payload["truncated"] is True, "a cut session must not read as a complete one"
    assert payload["output_chars"] == 500
    assert payload["returned_chars"] == 64
    assert len(str(payload["modules"])) == 64
    # The wrapper renames output, so the notice has to travel with the rename
    # rather than stay behind in the nested raw payload.
    assert "truncated" not in {key for key in payload if key == "raw"}


def test_a_dump_analysis_that_fits_is_not_labelled_truncated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The flag has to mean something, so it stays off when nothing was cut."""
    import subprocess

    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")

    def small(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"ok", stderr=b"")

    monkeypatch.setattr(windbg_module, "run_bounded", small)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)

    payload = WindbgClient(cdb).modules(dump)

    assert "truncated" not in payload
    assert payload["modules"] == "ok"


def test_a_failed_dump_is_not_saved_by_error_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """cdb exit 2 used to succeed if it printed anything to stdout.

    Measured: returncode=2, stdout "Could not open dump\\n", threads and
    modules both returned that string as the listing.
    """
    import subprocess

    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")

    def failed(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            args=[],
            returncode=2,
            stdout=b"Could not open dump\n",
            stderr=b"fatal",
        )

    monkeypatch.setattr(windbg_module, "run_bounded", failed)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    with pytest.raises(WindbgError) as info:
        WindbgClient(cdb).threads(dump)
    assert info.value.code == "backend_error"


def test_a_failed_live_probe_is_not_an_attach(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """cdb exit 2 used to report attached=True if it printed anything.

    Measured: returncode=2, stdout "Could not attach\\n", attach returned
    attached=True and live_threads returned that string as the listing.
    """
    import subprocess

    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")

    def failed(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            args=[],
            returncode=2,
            stdout=b"Could not attach\n",
            stderr=b"fatal",
        )

    monkeypatch.setattr(windbg_module, "run_bounded", failed)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    with pytest.raises(WindbgError) as info:
        WindbgClient(cdb).attach(7, allowed_pid=7)
    assert info.value.code == "backend_error"


def test_discovery_never_returns_a_store_package(monkeypatch: pytest.MonkeyPatch) -> None:
    store = r"C:\Program Files\WindowsApps\Microsoft.WinDbg_1.0_x64__abc\amd64\cdb.exe"
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    monkeypatch.setattr(windbg_module.shutil, "which", lambda _name: store)

    discovered = windbg_module._discover_cdb()

    assert discovered is None or "windowsapps" not in str(discovered).casefold()


def test_launch_failure_becomes_a_structured_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")
    client = WindbgClient(cdb)

    def denied(*_args: Any, **_kwargs: Any) -> Any:
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr(windbg_module, "run_bounded", denied)

    with pytest.raises(WindbgError) as exc:
        client.modules(dump)

    assert exc.value.code == "backend_error"
    assert "could not be launched" in exc.value.message
    assert exc.value.details["cdb"] == str(cdb)


def test_windbg_threads_description_says_to_check_truncated() -> None:
    """windbg.threads already cuts at 500000 chars, but the tool text hid that.

    Measured: 500-byte session, cap 64, truncated=true, while the
    description said "thread list as cdb prints it" -- so a model treats
    the slice as the whole stack.
    """
    from headless_re_mcp.core.service import AnalysisService
    from headless_re_mcp.tools.windbg import build_windbg_tools

    service = AnalysisService()
    try:
        tools = {item.name: item for item in build_windbg_tools(service)}
        doc = tools["windbg.threads"].handler.__doc__ or ""
    finally:
        service.close_all()
    assert "truncated" in doc


def test_windbg_modules_description_says_to_check_truncated() -> None:
    """windbg.modules already cuts at 500000 chars, but the tool text hid that.

    Measured: 500-byte session, cap 64, truncated=true, while the
    description said "module list as cdb prints it" -- so a model treats
    the slice as every loaded module.
    """
    from headless_re_mcp.core.service import AnalysisService
    from headless_re_mcp.tools.windbg import build_windbg_tools

    service = AnalysisService()
    try:
        tools = {item.name: item for item in build_windbg_tools(service)}
        doc = tools["windbg.modules"].handler.__doc__ or ""
    finally:
        service.close_all()
    assert "truncated" in doc


def test_windbg_live_threads_description_says_to_check_truncated() -> None:
    """windbg.live_threads already cuts at 500000 chars, but the text hid that.

    Measured: 500-byte session, cap 64, truncated=true, while the
    description said "thread list read non-invasively" -- so a model
    treats the slice as the whole live stack.
    """
    from headless_re_mcp.core.service import AnalysisService
    from headless_re_mcp.tools.windbg import build_windbg_tools

    service = AnalysisService()
    try:
        tools = {item.name: item for item in build_windbg_tools(service)}
        doc = tools["windbg.live_threads"].handler.__doc__ or ""
    finally:
        service.close_all()
    assert "truncated" in doc
