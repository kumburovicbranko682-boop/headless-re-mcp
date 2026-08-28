"""device.mounts must decode /proc/mounts honestly and stay bounded.

Octal-escaped paths are restored, ro is surfaced as readonly, a capped page
says has_more, and a read yielding no mounts (impossible on a live device) is
an error rather than a bare empty list.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import (
    AdbBackend,
    AdbError,
    _unescape_mount,
)
from headless_re_mcp.tools.device import build_device_tools

_MOUNTS = "\n".join(
    [
        "/dev/block/dm-0 / ext4 ro,seclabel,relatime 0 0",
        "tmpfs /dev tmpfs rw,seclabel,nosuid,relatime,mode=755 0 0",
        "/dev/block/dm-5 /data ext4 rw,seclabel,nosuid,nodev,noatime 0 0",
        r"/dev/block/vold /mnt/My\040Card vfat rw,nosuid,nodev 0 0",
        "garbage-line-too-short",
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
        assert command.endswith("/proc/mounts"), command
        return self._output


def _backend(output: str) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev(output)  # type: ignore[method-assign]
    return backend


def test_octal_escape_decoding_is_exact() -> None:
    """A space escaped as \\040 round-trips; unescaped tokens pass through."""
    assert _unescape_mount(r"/mnt/My\040Card") == "/mnt/My Card"
    assert _unescape_mount("/data") == "/data"
    assert _unescape_mount(r"a\011b") == "a\tb"


def test_mounts_parse_options_and_readonly() -> None:
    """/proc/mounts parses into device/mountpoint/fstype/options + readonly.

    Measured against AdbBackend.mounts over four valid lines (a short line is
    skipped): count 4, has_more False, the root mount is readonly True while
    /data is False, the options list is preserved verbatim, and the vfat card's
    \\040-escaped mountpoint is restored to a real space.
    """
    payload = _backend(_MOUNTS).mounts("emulator-5554", limit=500)
    assert payload["count"] == 4
    assert payload["has_more"] is False
    mounts = payload["mounts"]
    assert mounts[0] == {
        "device": "/dev/block/dm-0",
        "mountpoint": "/",
        "fstype": "ext4",
        "options": ["ro", "seclabel", "relatime"],
        "readonly": True,
    }
    assert mounts[2]["mountpoint"] == "/data"
    assert mounts[2]["readonly"] is False
    assert "nosuid" in mounts[2]["options"]
    assert mounts[3]["mountpoint"] == "/mnt/My Card"


def test_capped_page_says_has_more() -> None:
    """A full page reports has_more instead of posing as every mount."""
    lines = [
        f"/dev/block/loop{index} /mnt/x{index} ext4 ro 0 0" for index in range(50)
    ]
    payload = _backend("\n".join(lines)).mounts("emulator-5554", limit=5)
    assert payload["count"] == 5
    assert payload["has_more"] is True


def test_no_mounts_is_an_error() -> None:
    """An empty or refused read is backend_error, never an empty mount list.

    A live device always has mounts, so zero parsed rows means the read failed
    (permission denied, or an empty body). Returning [] would read as a device
    with no filesystems.
    """
    with pytest.raises(AdbError) as excinfo:
        _backend("cat: /proc/mounts: Permission denied").mounts("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_docstring_names_payload_and_honesty() -> None:
    doc = _tool_docstring("device.mounts")
    assert "mounts" in doc
    assert "readonly" in doc
    assert "has_more" in doc
