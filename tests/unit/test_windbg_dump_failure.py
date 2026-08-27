"""A failed cdb run must not read as an empty dump listing.

The dump path (`_run_dump`) used to return whatever cdb produced without
checking its exit code, while the live path (`_run_process`) already raised when
cdb failed with no output. And the wrappers -- threads/modules/disasm -- rename
`output` to their own field and drop `exit_code`/`stderr`, so a cdb that failed
(wrong bitness, corrupt dump) came back looking like a successful, empty
listing. `_carried` already lifts the truncation notice into those wrappers by
exactly this reasoning; these lock in that it now also carries the failure, and
that a total failure (non-zero exit, no output) raises on the dump path the way
it already did on the live path.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import headless_re_mcp.backends.windbg.client as windbg_module
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.windbg.client import WindbgClient, WindbgError


def _client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, completed: Completed) -> WindbgClient:
    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    monkeypatch.setattr(windbg_module, "run_bounded", lambda *a, **k: completed)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    return WindbgClient(cdb)


def _dump(tmp_path: Path) -> Path:
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")
    return dump


def test_modules_carries_tool_failed_on_nonzero_exit_with_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(
        tmp_path, monkeypatch, Completed(2, b"cdb: symbol errors", b"boom")
    )

    payload = client.modules(_dump(tmp_path))

    assert payload["modules"] == "cdb: symbol errors"
    assert payload["tool_failed"] is True
    assert payload["exit_code"] == 2
    assert payload["stderr"] == "boom"


def test_disasm_carries_tool_failed_on_nonzero_exit_with_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch, Completed(3, b"u failed", b""))

    payload = client.disasm(_dump(tmp_path), "0x1000", length=4)

    assert payload["disasm"] == "u failed"
    assert payload["tool_failed"] is True
    assert payload["exit_code"] == 3
    # stderr was empty, so it is not fabricated onto the reply.
    assert "stderr" not in payload


def test_dump_raises_when_cdb_failed_with_no_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch, Completed(2, b"", b"cannot open dump"))

    with pytest.raises(WindbgError) as caught:
        client.modules(_dump(tmp_path))

    assert caught.value.code == "backend_error"
    assert caught.value.details["exit_code"] == 2


def test_exit_code_one_is_tolerated_not_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # _run_process already treats 0 and 1 as acceptable cdb exits; the carry
    # must match, so a tolerated exit is not mislabelled a failure.
    client = _client(tmp_path, monkeypatch, Completed(1, b"lm output", b""))

    payload = client.modules(_dump(tmp_path))

    assert payload["modules"] == "lm output"
    assert "tool_failed" not in payload


def test_live_modules_carries_tool_failed_on_nonzero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch, Completed(2, b"live lm", b"warn"))

    payload = client.live_modules(4242, allowed_pid=4242)

    assert payload["modules"] == "live lm"
    assert payload["tool_failed"] is True
    assert payload["exit_code"] == 2
    assert payload["stderr"] == "warn"


def test_open_dump_reports_the_exit_code_when_output_survived(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # open_dump surfaces exit_code directly; a non-zero-with-output run is kept
    # (not raised) so the caller sees both the partial text and the failure.
    client = _client(tmp_path, monkeypatch, Completed(2, b"partial", b"err"))

    payload = client.open_dump(_dump(tmp_path), ["lm"])

    assert payload["output"] == "partial"
    assert payload["exit_code"] == 2


def _wrapper_docstrings() -> dict[str, str]:
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
                if keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
                    docs[str(keyword.value.value)] = ast.get_docstring(node) or ""
    return docs


def test_wrapper_docstrings_name_tool_failed() -> None:
    docs = _wrapper_docstrings()
    for name in (
        "windbg.threads",
        "windbg.modules",
        "windbg.disasm",
        "windbg.live_threads",
        "windbg.live_modules",
        "windbg.live_disasm",
    ):
        assert "tool_failed" in docs[name], name
