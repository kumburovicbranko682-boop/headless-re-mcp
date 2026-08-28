"""device.users must decode pm list users honestly and stay bounded.

Flag bits are decoded while the raw hex is preserved, names containing colons
survive, a capped page says has_more, and a read yielding no users (impossible
on a live device) is an error rather than a bare empty list.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools

_USERS = "\n".join(
    [
        "Users:",
        "\tUserInfo{0:Owner:c13} running",
        "\tUserInfo{10:Work profile:30}",
        "\tUserInfo{11:Guest:404} running",
        "noise that is not a user line",
    ]
)


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


class _FakeDev:
    def __init__(self, output: str) -> None:
        self._output = output

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        command = args if isinstance(args, str) else " ".join(args)
        assert command == "pm list users", command
        return self._output


def _backend(output: str) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev(output)  # type: ignore[method-assign]
    return backend


def test_users_parse_flags_running_and_names() -> None:
    """pm list users parses id/name/flags/running with decoded flag names.

    Measured against AdbBackend.users over three UserInfo lines (a noise line
    is skipped): count 3, has_more False. The owner's c13 decodes to
    PRIMARY/ADMIN/INITIALIZED/FULL/SYSTEM and is running; the work profile's
    0x30 decodes to INITIALIZED/MANAGED_PROFILE and is not running; the guest
    carries GUEST. The raw hex is preserved verbatim.
    """
    payload = _backend(_USERS).users("emulator-5554", limit=100)
    assert payload["count"] == 3
    assert payload["has_more"] is False
    users = payload["users"]
    assert users[0] == {
        "id": 0,
        "name": "Owner",
        "flags": "c13",
        "flag_names": ["PRIMARY", "ADMIN", "INITIALIZED", "FULL", "SYSTEM"],
        "running": True,
    }
    assert users[1]["id"] == 10
    assert users[1]["name"] == "Work profile"
    assert users[1]["flag_names"] == ["INITIALIZED", "MANAGED_PROFILE"]
    assert users[1]["running"] is False
    assert "GUEST" in users[2]["flag_names"]


def test_name_with_colon_survives() -> None:
    """A user name containing a colon still parses; flags is the last field."""
    payload = _backend("\tUserInfo{12:a:b:20} running").users("emulator-5554")
    assert payload["users"][0]["name"] == "a:b"
    assert payload["users"][0]["flags"] == "20"
    assert payload["users"][0]["flag_names"] == ["MANAGED_PROFILE"]


def test_capped_page_says_has_more() -> None:
    """A full page reports has_more instead of posing as every user."""
    lines = [f"\tUserInfo{{{index}:u{index}:400}} running" for index in range(20)]
    payload = _backend("\n".join(lines)).users("emulator-5554", limit=5)
    assert payload["count"] == 5
    assert payload["has_more"] is True


def test_no_users_is_an_error() -> None:
    """A read with no UserInfo lines is backend_error, never an empty list.

    A live device always has user 0, so zero parsed users means the read
    failed or returned an unexpected shape. Returning [] would read as a
    device with no users.
    """
    with pytest.raises(AdbError) as excinfo:
        _backend("Users:\n(nothing parseable here)").users("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_docstring_names_payload_and_honesty() -> None:
    doc = _tool_docstring("device.users")
    assert "users" in doc
    assert "flag_names" in doc
    assert "has_more" in doc
