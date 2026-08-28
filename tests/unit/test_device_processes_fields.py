"""device.processes lists what is running on the device right now (ps -A).

device.packages reports what is installed; device.processes reads `ps -A` and
shapes each row into {pid, name, user, ppid} so an installed app id becomes a
running target -- the pid frida.attach/frida.spawn need. These cover the
header-column parse (order is not fixed across toybox versions), the
name-with-spaces (ARGS-style) join, the name column that is not last, the
name_filter, paging and pid sort, the malformed-row and no-PID-column paths, the
collection cap, the argv (no-shell-injection) contract, service routing, and the
read-only class.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb import client as adb_client
from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_device_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
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
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


class _Dev:
    """A device whose shell() returns canned ps output and records argv."""

    def __init__(self, output: str, calls: list[Any] | None = None) -> None:
        self._output = output
        self._calls = calls if calls is not None else []

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        self._calls.append(args)
        return self._output


def _backend(output: str, calls: list[Any] | None = None) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _Dev(output, calls)  # type: ignore[method-assign]
    return backend


# A realistic toybox `ps -A` layout: USER first, PID second, NAME last.
_TOYBOX_PS = (
    "USER           PID  PPID     VSZ    RSS WCHAN            ADDR S NAME\n"
    "root             1     0   10668   1096 0                   0 S init\n"
    "root             2     0       0      0 0                   0 S [kthreadd]\n"
    "u0_a123      12345   567 1234567  45678 0                   0 S com.example.app\n"
)


def test_processes_parses_pid_name_user_ppid_by_header() -> None:
    payload = _backend(_TOYBOX_PS).processes("emulator-5554")
    assert payload["count"] == 3
    assert payload["total"] == 3
    rows = {row["pid"]: row for row in payload["processes"]}
    app = rows[12345]
    assert app["name"] == "com.example.app"
    assert app["user"] == "u0_a123"
    assert app["ppid"] == 567
    # A bracketed kernel thread name survives intact.
    assert rows[2]["name"] == "[kthreadd]"


def test_processes_are_ordered_by_pid() -> None:
    payload = _backend(_TOYBOX_PS).processes("emulator-5554")
    pids = [row["pid"] for row in payload["processes"]]
    assert pids == sorted(pids)
    assert pids[0] == 1


def test_processes_join_a_name_with_spaces_when_name_is_the_last_column() -> None:
    # An ARGS-style ps whose last column carries the full command line: every
    # column before it is a single token, so the name is everything to EOL.
    output = (
        "USER  PID ARGS\n"
        "root  1 /system/bin/init second_stage\n"
    )
    payload = _backend(output).processes("emulator-5554")
    assert payload["processes"][0]["name"] == "/system/bin/init second_stage"


def test_processes_take_a_single_token_when_name_is_not_the_last_column() -> None:
    # NAME sits before another column, and there is no USER/PPID column: the row
    # is {pid, name} only, and the name is that one token, not the trailing one.
    output = (
        "PID NAME S\n"
        "100 zygote64 S\n"
    )
    payload = _backend(output).processes("emulator-5554")
    row = payload["processes"][0]
    assert row == {"pid": 100, "name": "zygote64"}


def test_processes_name_filter_is_case_insensitive_substring_before_paging() -> None:
    output = (
        "USER PID PPID NAME\n"
        "u0_a1 10 1 com.example.app\n"
        "u0_a2 11 1 com.example.app:svc\n"
        "root 12 1 surfaceflinger\n"
    )
    payload = _backend(output).processes("emulator-5554", name_filter="COM.EXAMPLE")
    names = [row["name"] for row in payload["processes"]]
    assert names == ["com.example.app", "com.example.app:svc"]
    # total is the match count, not the whole table.
    assert payload["total"] == 2


def test_processes_page_with_offset_and_limit() -> None:
    rows = "".join(f"root {pid} 1 proc{pid}\n" for pid in range(100, 110))
    output = "USER PID PPID NAME\n" + rows
    payload = _backend(output).processes("emulator-5554", offset=2, limit=3)
    assert payload["offset"] == 2
    assert payload["count"] == 3
    assert payload["total"] == 10
    assert payload["has_more"] is True
    assert [row["pid"] for row in payload["processes"]] == [102, 103, 104]


def test_processes_skip_malformed_rows_and_blank_lines() -> None:
    output = (
        "USER PID PPID NAME\n"
        "\n"
        "garbage line without a numeric pid in slot\n"
        "root 42 1 realproc\n"
    )
    payload = _backend(output).processes("emulator-5554")
    # Only the row whose PID slot is numeric survives.
    assert [row["pid"] for row in payload["processes"]] == [42]


def test_processes_without_a_pid_column_is_backend_error() -> None:
    with pytest.raises(AdbError) as info:
        _backend("FOO BAR BAZ\nroot 1 init\n").processes("emulator-5554")
    assert info.value.code == "backend_error"


def test_processes_empty_output_is_an_empty_list_not_an_error() -> None:
    payload = _backend("").processes("emulator-5554")
    assert payload["processes"] == []
    assert payload["count"] == 0
    assert payload["total"] == 0
    assert payload["has_more"] is False


def test_processes_cap_a_pathological_count(monkeypatch: Any) -> None:
    monkeypatch.setattr(adb_client, "_MAX_PROCESSES", 3)
    rows = "".join(f"root {pid} 1 proc{pid}\n" for pid in range(100, 110))
    output = "USER PID PPID NAME\n" + rows
    payload = _backend(output).processes("emulator-5554", limit=1000)
    assert payload["total"] == 3
    assert payload["collection_truncated"] is True


def test_processes_page_limit_is_capped(monkeypatch: Any) -> None:
    monkeypatch.setattr(adb_client, "_MAX_PROCESSES_PAGE", 2)
    rows = "".join(f"root {pid} 1 proc{pid}\n" for pid in range(100, 110))
    output = "USER PID PPID NAME\n" + rows
    payload = _backend(output).processes("emulator-5554", limit=1000)
    assert payload["count"] == 2
    assert payload["total"] == 10
    assert payload["has_more"] is True


def test_processes_run_ps_as_argv_not_a_shell_string() -> None:
    calls: list[Any] = []
    _backend(_TOYBOX_PS, calls).processes("emulator-5554")
    assert calls == [["ps", "-A"]]


def test_service_device_processes_routes_to_the_owned_backend() -> None:
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        calls: list[Any] = []

        def fake(serial: str, *, offset: int, limit: int, name_filter: str) -> Any:
            calls.append((serial, offset, limit, name_filter))
            return {
                "processes": [{"pid": 1, "name": "init"}],
                "count": 1,
                "total": 1,
                "offset": 0,
                "has_more": False,
            }

        service._adb_backend.processes = fake  # type: ignore[method-assign]
        result = service.device_processes(
            "emulator-5554", offset=0, limit=50, name_filter="init"
        )
        assert result.ok and result.data is not None
        assert result.data["processes"][0]["name"] == "init"
        assert calls == [("emulator-5554", 0, 50, "init")]
    finally:
        service.close_all()


def test_processes_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("device.processes").split())
    assert "ps -A" in doc
    assert "frida.attach" in doc
    assert "name_filter" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "device.processes" in _READ_ONLY_NAMES
