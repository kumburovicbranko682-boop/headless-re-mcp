"""AdbBackend device read-outs must page and truncate honestly.

``device.logcat`` / ``device.packages`` / ``device.force_stop`` all summarise a
shell dump, and the catalog promises the fields a caller reads to know whether
it saw everything: ``truncated`` on logcat, ``has_more`` on packages, and the
tri-state ``stopped`` (true / false / null) on force-stop. These paths are
driven entirely by ``device.shell`` text, so they are pinned here with an
injected fake device -- no adbutils, no emulator -- exactly where the real
parsing lives. A page that filled the cap but reported ``has_more`` false, or a
force-stop that could not read the process list but claimed ``stopped`` true,
is the failure these guard against.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.backends.adb.client import _MAX_LOGCAT_CHARS, AdbBackend


class _ScriptedDev:
    """A device whose ``shell`` answers by the command's first tokens.

    ``responses`` maps a matcher (the leading tokens of the shell argv, or the
    whole string for a bare command) to canned stdout; ``raise_for`` names
    commands that must fail the way a stalled or missing binary does. Every call
    is recorded so a test can prove which argv the backend actually sent -- the
    ``-3`` third-party flag is only visible there.
    """

    def __init__(
        self,
        responses: dict[tuple[str, ...], str],
        *,
        raise_for: tuple[tuple[str, ...], ...] = (),
    ) -> None:
        self._responses = responses
        self._raise_for = set(raise_for)
        self.calls: list[list[str] | str] = []

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        self.calls.append(args)
        # The backend sends some commands as an argv list and others as one
        # string; match both by their leading tokens so a matcher reads the same.
        tokens = tuple(args) if isinstance(args, list) else tuple(str(args).split())
        if tokens in self._raise_for:
            raise RuntimeError("device stalled")
        for matcher, output in self._responses.items():
            if tokens[: len(matcher)] == matcher:
                return output
        return ""


def _backend_with(dev: _ScriptedDev) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def test_logcat_flags_the_character_cap_and_keeps_a_bounded_tail() -> None:
    """A dump past the char cap says truncated and returns only the tail.

    Measured: 200 lines of 2 000 chars (~400 KB) with the 200 000-char cap ->
    truncated True, the returned text is the last 200 000 chars, and every
    returned line is one of the originals (the head was dropped, not mangled
    into a new line count that hides the loss).
    """
    line = "x" * 2000
    dump = "\n".join(f"{line}-{index}" for index in range(200))
    assert len(dump) > _MAX_LOGCAT_CHARS
    dev = _ScriptedDev({("logcat",): dump})
    payload = _backend_with(dev).logcat("emulator-5554", lines=200)
    assert payload["truncated"] is True
    assert payload["requested"] == 200
    assert 0 < len(payload["lines"]) <= 200
    # The tail is a suffix of the dump, so each surviving line is an original one.
    originals = set(dump.splitlines())
    assert all(entry in originals for entry in payload["lines"][1:])


def test_logcat_returns_everything_when_it_fits() -> None:
    """A small dump is not labelled truncated and loses no line."""
    dump = "\n".join(f"line-{index}" for index in range(10))
    dev = _ScriptedDev({("logcat",): dump})
    payload = _backend_with(dev).logcat("emulator-5554", lines=200)
    assert payload["truncated"] is False
    assert payload["lines"] == [f"line-{index}" for index in range(10)]


def test_logcat_clamps_the_requested_line_count() -> None:
    """A caller asking past the 5 000-line ceiling is told the clamped value."""
    dev = _ScriptedDev({("logcat",): "only-line"})
    payload = _backend_with(dev).logcat("emulator-5554", lines=99999)
    assert payload["requested"] == 5000
    # The device-side -t argument carries the same clamped number, never 99999.
    assert dev.calls == [["logcat", "-d", "-t", "5000"]]


def test_packages_reports_has_more_and_sorts_the_page() -> None:
    """A list longer than the cap says has_more and comes back sorted."""
    listing = "\n".join(
        f"package:{name}" for name in ("com.e", "com.d", "com.c", "com.b", "com.a")
    )
    dev = _ScriptedDev({("pm", "list", "packages"): listing})
    payload = _backend_with(dev).packages("emulator-5554", limit=3)
    assert payload["count"] == 3
    assert payload["has_more"] is True
    assert payload["third_party_only"] is False
    assert payload["packages"] == sorted(payload["packages"])
    assert set(payload["packages"]) <= {"com.a", "com.b", "com.c", "com.d", "com.e"}


def test_packages_complete_list_is_not_labelled_partial() -> None:
    """A list within the cap reports has_more false and keeps every name."""
    listing = "package:com.b\npackage:com.a"
    dev = _ScriptedDev({("pm", "list", "packages"): listing})
    payload = _backend_with(dev).packages("emulator-5554", limit=500)
    assert payload["has_more"] is False
    assert payload["count"] == 2
    assert payload["packages"] == ["com.a", "com.b"]


def test_packages_third_party_only_passes_the_flag() -> None:
    """third_party_only must reach adb as ``pm list packages -3``.

    Dropping the flag would silently list every system package while the
    envelope still claimed third_party_only true.
    """
    dev = _ScriptedDev({("pm", "list", "packages", "-3"): "package:com.thirdparty"})
    payload = _backend_with(dev).packages("emulator-5554", third_party_only=True)
    assert payload["third_party_only"] is True
    assert payload["packages"] == ["com.thirdparty"]
    assert dev.calls == ["pm list packages -3"]


def test_force_stop_reports_survivors_as_not_stopped() -> None:
    """pidof still returning pids means the package was not stopped."""
    dev = _ScriptedDev(
        {
            ("am", "force-stop"): "",
            ("pidof",): "1234 5678",
        }
    )
    payload = _backend_with(dev).force_stop("emulator-5554", "com.example.app")
    assert payload["stopped"] is False
    assert payload["remaining_pids"] == [1234, 5678]


def test_force_stop_reports_a_clean_stop() -> None:
    """An empty pidof means nothing survived: stopped true, no remaining pids."""
    dev = _ScriptedDev(
        {
            ("am", "force-stop"): "",
            ("pidof",): "",
        }
    )
    payload = _backend_with(dev).force_stop("emulator-5554", "com.example.app")
    assert payload["stopped"] is True
    assert payload["remaining_pids"] == []


def test_force_stop_falls_back_to_ps_when_pidof_is_missing() -> None:
    """Older devices without pidof still get a survivor read from ps -A.

    ``pidof: not found`` is a missing-binary message, not an empty result, so
    the fallback parses the process table and the PID (second column) is read
    from the matching row rather than reporting a clean stop by default.
    """
    ps_table = (
        "USER   PID  PPID VSZ RSS WCHAN ADDR S NAME\n"
        "u0_a12 4321 1234 0   0   ffff  0    S com.example.app\n"
    )
    dev = _ScriptedDev(
        {
            ("am", "force-stop"): "",
            ("pidof",): "/system/bin/sh: pidof: not found",
            ("ps", "-A"): ps_table,
        }
    )
    payload = _backend_with(dev).force_stop("emulator-5554", "com.example.app")
    assert payload["stopped"] is False
    assert payload["remaining_pids"] == [4321]


def test_force_stop_is_honest_when_the_process_list_is_unreadable() -> None:
    """A pidof that fails outright leaves stopped null, not a false success.

    force-stop returning is not proof the package died; when the follow-up
    process read cannot run, the tri-state must stay null rather than collapse
    to true and tell a caller the app is gone.
    """
    dev = _ScriptedDev(
        {("am", "force-stop"): ""},
        raise_for=(("pidof", "com.example.app"),),
    )
    payload = _backend_with(dev).force_stop("emulator-5554", "com.example.app")
    assert payload["stopped"] is None
    assert "remaining_pids" not in payload
    assert "note" in payload


def test_force_stop_is_null_when_pidof_returns_a_host_error() -> None:
    """An "adb: ... not found" host line is not a confirmed stop.

    adbutils can return the adb host's own error as stdout without raising, and
    the "adb: device 'x' not found" form contains "not found" -- the same token
    the missing-pidof branch keys on. Reading it as "pidof is missing" ran the
    ps fallback, which for an offline device came back empty and reported
    stopped true for a package the backend never actually checked. It must stay
    null, the honest answer when the process list cannot be read.
    """
    dev = _ScriptedDev(
        {
            ("am", "force-stop"): "",
            ("pidof",): "adb: device 'emulator-5554' not found",
        }
    )
    payload = _backend_with(dev).force_stop("emulator-5554", "com.example.app")
    assert payload["stopped"] is None
    assert "remaining_pids" not in payload
    assert "note" in payload
    # A host error must not be mistaken for a missing pidof and trigger ps -A.
    assert not any(
        (tuple(call) if isinstance(call, list) else tuple(str(call).split()))[:2] == ("ps", "-A")
        for call in dev.calls
    )


def test_force_stop_is_null_when_the_ps_fallback_returns_a_host_error() -> None:
    """A device that truly lacks pidof but goes offline for ps stays null.

    The genuine "/system/bin/sh: pidof: not found" message still routes to the
    ps fallback, but if ps -A then answers with a host error line rather than a
    process table, an empty parse read as a clean stop. force-stop returning is
    not proof the package died, so the tri-state must stay null.
    """
    dev = _ScriptedDev(
        {
            ("am", "force-stop"): "",
            ("pidof",): "/system/bin/sh: pidof: not found",
            ("ps", "-A"): "error: device offline",
        }
    )
    payload = _backend_with(dev).force_stop("emulator-5554", "com.example.app")
    assert payload["stopped"] is None
    assert "remaining_pids" not in payload
    assert "note" in payload
