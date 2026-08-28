"""device.security must report SELinux/su honestly and not guess.

The SELinux mode is normalised while the raw reply is preserved, an absent su
is a real False (not unavailable), a refused probe is named under unavailable,
and both probes failing is an error rather than a made-up posture.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

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


class _FakeDev:
    """Answers getenforce and ``command -v su`` from a canned map."""

    def __init__(self, replies: dict[str, Any]) -> None:
        self._replies = replies

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        command = args if isinstance(args, str) else " ".join(args)
        reply = self._replies.get(command)
        if isinstance(reply, Exception):
            raise reply
        assert reply is not None, f"unexpected command: {command!r}"
        return reply


def _backend(replies: dict[str, Any]) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev(replies)  # type: ignore[method-assign]
    return backend


def test_enforcing_and_su_absent() -> None:
    """A hardened device: Enforcing, and su absent is a real False.

    command -v su prints nothing when su is not on PATH, which is a successful
    probe, so su_on_path is False (not unavailable) and there is no unavailable
    key. selinux_raw preserves the exact getenforce reply.
    """
    payload = _backend(
        {"getenforce": "Enforcing\n", "command -v su": ""}
    ).security("emulator-5554")
    assert payload["selinux"] == "Enforcing"
    assert payload["selinux_raw"] == "Enforcing"
    assert payload["su_on_path"] is False
    assert payload["su_path"] is None
    assert "unavailable" not in payload


def test_permissive_and_su_present() -> None:
    """A rooted device: Permissive, su resolved to a path."""
    payload = _backend(
        {"getenforce": "Permissive", "command -v su": "/system/xbin/su\n"}
    ).security("emulator-5554")
    assert payload["selinux"] == "Permissive"
    assert payload["su_on_path"] is True
    assert payload["su_path"] == "/system/xbin/su"


def test_unexpected_getenforce_is_null_but_raw_kept() -> None:
    """getenforce missing yields selinux null + unavailable, raw preserved.

    An unrecognised reply (e.g. "getenforce: not found") is not force-fit to a
    mode: selinux is null, selinux lands in unavailable, and the raw text is
    still surfaced. su probing still succeeds, so the call is not an error.
    """
    payload = _backend(
        {
            "getenforce": "/system/bin/sh: getenforce: not found",
            "command -v su": "",
        }
    ).security("emulator-5554")
    assert payload["selinux"] is None
    assert payload["selinux_raw"].endswith("not found")
    assert payload["unavailable"] == ["selinux"]
    assert payload["su_on_path"] is False


def test_both_probes_failing_is_an_error() -> None:
    """Both shell calls raising is backend_error, never a fabricated posture."""
    boom = AdbError("backend_error", "adb shell failed")
    with pytest.raises(AdbError) as excinfo:
        _backend(
            {"getenforce": boom, "command -v su": boom}
        ).security("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_docstring_names_payload_and_honesty() -> None:
    doc = _tool_docstring("device.security")
    assert "selinux" in doc
    assert "su_on_path" in doc
    assert "unavailable" in doc
