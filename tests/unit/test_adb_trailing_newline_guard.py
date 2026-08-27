"""ADB identifier validators must reject a trailing newline, not just tolerate it.

Python's ``$`` anchor matches at the end of the string *or* immediately before a
final newline, so a ``$``-anchored guard accepts ``"value\\n"`` -- the newline
rides along into whatever the value feeds. For the specs that reach the adb wire
protocol (``forward``) and, worse, the ``su -c '...'`` string
``frida.server.ensure`` builds, that trailing newline splits the line into a
second command: exactly the "smuggle extra arguments" outcome the module
docstring says the patterns prevent. The validators now anchor with ``\\Z`` (the
true end of string, the same anchor the r2 command allowlist uses), so a value
carrying a newline is refused up front.

``_check_serial`` / ``_check_package`` strip first, so they were never reachable
with a trailing newline; the compiled-pattern checks below still pin the anchor
so a future refactor that drops the strip cannot silently reopen the hole.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import (
    _BIND_HOST_RE,
    _PACKAGE_RE,
    _SERIAL_RE,
    AdbBackend,
    AdbError,
)


class _Dev:
    """Minimal device stand-in; the validators raise before it is used."""

    def forward(self, local: str, remote: str, timeout: float | None = None) -> None:
        del local, remote, timeout


def _backend() -> AdbBackend:
    backend = AdbBackend()
    backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
    return backend


@pytest.mark.parametrize(
    "pattern,value",
    [
        (_SERIAL_RE, "emulator-5554\n"),
        (_PACKAGE_RE, "com.evil.app\n"),
        (_BIND_HOST_RE, "127.0.0.1\n"),
    ],
)
def test_identifier_patterns_bind_to_the_true_end_of_string(
    pattern: Any, value: str
) -> None:
    # The trailing-newline form is rejected...
    assert pattern.match(value) is None
    # ...while the clean identifier still matches, so this is a tightening of the
    # anchor and not a narrowing of what a legitimate id may contain.
    assert pattern.match(value.rstrip("\n")) is not None


@pytest.mark.parametrize(
    "local,remote",
    [
        ("tcp:5555\n", "tcp:27042"),
        ("tcp:27042", "tcp:5555\n"),
        ("localabstract:frida\n", "tcp:27042"),
        ("tcp:27042", "jdwp:1234\n"),
    ],
)
def test_forward_specs_reject_a_trailing_newline(local: str, remote: str) -> None:
    backend = _backend()
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", local, remote)
    assert caught.value.code == "invalid_params"
    # Nothing was reserved for a spec that never validated.
    assert backend._forwards == []


def test_ensure_frida_server_rejects_a_newline_in_remote_path() -> None:
    backend = _backend()
    with pytest.raises(AdbError) as caught:
        backend.ensure_frida_server(
            "emulator-5554",
            server_binary=None,
            remote_path="/data/local/tmp/frida-server\n",
        )
    assert caught.value.code == "invalid_params"
    assert caught.value.details.get("remote_path") == "/data/local/tmp/frida-server\n"


def test_ensure_frida_server_rejects_a_newline_in_bind_host() -> None:
    backend = _backend()
    with pytest.raises(AdbError) as caught:
        backend.ensure_frida_server(
            "emulator-5554",
            server_binary=None,
            bind_host="127.0.0.1\n",
        )
    assert caught.value.code == "invalid_params"
    assert caught.value.details.get("bind_host") == "127.0.0.1\n"
