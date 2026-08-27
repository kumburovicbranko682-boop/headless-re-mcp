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
    assert "raw" not in payload


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


def _clamp_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[WindbgClient, Path, dict[str, float]]:
    import subprocess

    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")
    captured: dict[str, float] = {}

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        captured["timeout"] = kwargs.get("timeout")
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"ok", stderr=b"")

    monkeypatch.setattr(windbg_module, "run_bounded", fake_run)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    return WindbgClient(cdb), dump, captured


def test_an_agent_supplied_dump_deadline_is_clamped_to_the_schema_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The agent transport skips the dump tools' le=300 bound; unclamped, a hung
    cdb would hold the dump file for as long as the caller named."""
    client, dump, captured = _clamp_fixture(tmp_path, monkeypatch)

    client.modules(dump, timeout=10**9)
    assert captured["timeout"] == windbg_module._MAX_DUMP_TIMEOUT_S == 300.0

    client.threads(dump, timeout=float("inf"))
    assert captured["timeout"] == 300.0

    client.modules(dump, timeout=60.0)
    assert captured["timeout"] == 60.0


def test_an_agent_supplied_live_deadline_is_clamped_to_the_schema_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Live tools declare le=120 and cdb stays non-invasively attached to the
    debuggee for the whole deadline, so the ceiling is tighter than for dumps."""
    client, _dump, captured = _clamp_fixture(tmp_path, monkeypatch)

    client.live_modules(41, allowed_pid=41, timeout=10**9)
    assert captured["timeout"] == windbg_module._MAX_LIVE_TIMEOUT_S == 120.0

    client.live_threads(41, allowed_pid=41, timeout=30.0)
    assert captured["timeout"] == 30.0


@pytest.mark.parametrize("bad", [0.0, -5.0, float("nan")])
def test_a_non_positive_or_nan_deadline_is_rejected_before_cdb_is_launched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: float
) -> None:
    client, dump, captured = _clamp_fixture(tmp_path, monkeypatch)

    with pytest.raises(WindbgError) as dump_err:
        client.modules(dump, timeout=bad)
    assert dump_err.value.code == "invalid_params"

    with pytest.raises(WindbgError) as live_err:
        client.live_modules(41, allowed_pid=41, timeout=bad)
    assert live_err.value.code == "invalid_params"

    assert not captured, "a bad deadline must be rejected before cdb is launched"


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


def test_attach_puts_cdb_text_in_output_not_version_or_platform(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The catalog said version and platform; those fields are not on the reply.

    Measured: a vertarget/version probe answers with output holding the cdb
    session text. Looking for version after a successful attach reads as the
    probe having returned nothing about the target.
    """
    from headless_re_mcp.backends.common.bounded_run import Completed

    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    text = b"Windows 10 Version 19045 MP (8 procs) Free x64\n"

    def fake_run(*args: Any, **kwargs: Any) -> Completed:
        return Completed(0, text, b"")

    monkeypatch.setattr(windbg_module, "run_bounded", fake_run)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)

    payload = WindbgClient(cdb).attach(4242, allowed_pid=4242)

    assert payload["output"] == text.decode()
    assert "version" not in payload
    assert "platform" not in payload


def test_windbg_descriptions_name_the_fields_cdb_text_comes_back_in() -> None:
    import ast

    from headless_re_mcp.tools.windbg import build_windbg_tools

    source = Path(build_windbg_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    docs: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                ):
                    docs[str(keyword.value.value)] = ast.get_docstring(node) or ""

    assert "version and platform" not in docs["windbg.attach"]
    assert "Answers with output" in docs["windbg.attach"]
    assert "Answers with threads" in docs["windbg.threads"]
    assert "Answers with modules" in docs["windbg.modules"]
    assert "Answers with disasm" in docs["windbg.disasm"]
    assert "Answers with threads" in docs["windbg.live_threads"]
    assert "Answers with modules" in docs["windbg.live_modules"]
    assert "Answers with disasm" in docs["windbg.live_disasm"]


def test_windbg_listing_does_not_echo_the_nested_session_as_raw(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The wrapper renamed output to modules and then nested the session again.

    Measured: modules() puts the cdb text in modules and a second copy under
    raw.output, plus dump, stderr and exit_code. A 200-char session therefore
    occupies the MCP envelope twice. An overnight pass that serialises the
    reply pays for the listing twice.
    """
    from headless_re_mcp.backends.common.bounded_run import Completed

    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")
    text = "m" * 200

    def fake_run(*args: Any, **kwargs: Any) -> Completed:
        return Completed(0, text.encode(), b"")

    monkeypatch.setattr(windbg_module, "run_bounded", fake_run)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)

    payload = WindbgClient(cdb).modules(dump)
    assert payload["modules"] == text
    assert "raw" not in payload
    source = Path(WindbgClient.modules.__code__.co_filename).read_text(encoding="utf-8")
    assert '"raw": data' not in source
