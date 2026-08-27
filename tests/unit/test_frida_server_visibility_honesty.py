"""``_frida_server_visible`` is tri-state; a host error is null, not "absent".

``frida.server.ensure`` reports ``running`` true/false/null from
``_frida_server_visible``, which decides by looking for "frida-server" in the
device process list. adbutils can hand back the adb host's own "adb:"/"error:"
line as stdout without raising (an offline device answers ``ps`` that way), and
"frida-server" is not in that line -- so the probe read a host error as a
definite "not running" (false) instead of "could not check" (null). That is the
same misreport ``pm path`` and ``force_stop`` grew a guard against: a caller
that reads false restarts a frida-server that may already be up, or gives up on
a device it never actually queried.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.backends.adb.client import AdbBackend, _frida_server_visible


class _ScriptedDev:
    """A device whose ``shell`` answers canned stdout by the command's tokens."""

    def __init__(self, responses: dict[tuple[str, ...], str]) -> None:
        self._responses = responses
        self.calls: list[str] = []

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        tokens = tuple(args) if isinstance(args, list) else tuple(str(args).split())
        self.calls.append(args if isinstance(args, str) else " ".join(args))
        for matcher, output in self._responses.items():
            if tokens[: len(matcher)] == matcher:
                return output
        return ""


def test_visible_is_null_when_ps_returns_a_host_error() -> None:
    """An "error: device offline" ps answer is unverifiable, not "not running"."""
    dev = _ScriptedDev({("ps", "-A"): "error: device offline", ("ps",): "error: device offline"})
    assert _frida_server_visible(dev) is None


def test_visible_is_null_when_the_ps_fallback_returns_a_host_error() -> None:
    """ps -A empty (no match) then a host error on the bare ps fallback stays null."""
    dev = _ScriptedDev({("ps", "-A"): "", ("ps",): "adb: device 'emulator-5554' not found"})
    assert _frida_server_visible(dev) is None


def test_visible_is_true_when_frida_server_is_in_the_process_table() -> None:
    """A real hit still reports true -- the guard must not swallow the positive."""
    table = "USER PID NAME\nroot 900 /data/local/tmp/frida-server\n"
    dev = _ScriptedDev({("ps", "-A"): table})
    assert _frida_server_visible(dev) is True


def test_visible_is_false_when_the_process_table_is_read_without_frida() -> None:
    """A genuinely read table with no frida-server is an honest false, not null."""
    table = "USER PID NAME\nu0_a1 1000 com.example.app\n"
    dev = _ScriptedDev({("ps", "-A"): table, ("ps",): table})
    assert _frida_server_visible(dev) is False


def _backend_with(dev: _ScriptedDev) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def test_ensure_frida_server_reports_null_when_the_probe_cannot_read_ps() -> None:
    """After launch, a host error on the confirm probe must not read as not-running.

    With no server_binary the push step is skipped; the launch command returns
    cleanly, and the post-launch visibility probe answers with a host-error line.
    running must stay null (could not confirm), not false, and the note must say
    the process list was unreadable rather than "not visible in ps".
    """
    dev = _ScriptedDev(
        {
            ("ps", "-A"): "error: device offline",
            ("ps",): "error: device offline",
        }
    )
    payload = _backend_with(dev).ensure_frida_server("emulator-5554", port=27042)
    assert payload["running"] is None
    assert "could not read the device process list" in payload["note"]
