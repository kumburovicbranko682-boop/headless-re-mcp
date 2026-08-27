"""The frida target set is the client's last line of defense; pin its refusals.

The device model authorizes a pid set per session (the pids it spawned/attached)
and hands that set to the client on every call; _authorize is what actually
refuses a pid outside it, and _require is the local single-pid equivalent. That
enforcement -- the whole "explicit, bounded target" guarantee -- had no test:
the service-layer tests stop at "a device was connected", and nothing checked
that an *explicit, unauthorized* pid is turned away by the backend.

None of this needs a real frida: _authorize/_require run before the device is
resolved or any frida call is made. Forcing _available=True with a sentinel
module reaches the permission branch (the availability check passes, then no
real frida object is touched because authorization fails first), and
monkeypatching _resolve_device proves the refusal precedes device resolution --
a regression that resolved the device first would leak device state to an
unauthorized request.

The two authorization paths order their checks differently on purpose, and both
orderings are pinned here: the local _require is fail-closed on authorization
(an unauthorized pid is refused even with frida absent, so the gate never
depends on backend presence), while the device _authorize reports the missing
backend first. Both refuse the unauthorized pid; only the code when frida is
absent differs.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


def _client_with_sentinel_frida() -> FridaClient:
    """A client that believes frida is present without importing it: enough to
    pass the availability gate and reach the authorization branch, never enough
    to make a real frida call (authorization fails before any device work)."""
    client = FridaClient()
    client._available = True
    client._frida = object()
    return client


class TestDeviceAuthorization:
    def test_java_enumerate_refuses_a_pid_outside_the_set_before_resolving(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _client_with_sentinel_frida()
        resolved: list[object] = []
        monkeypatch.setattr(client, "_resolve_device", lambda *a, **k: resolved.append(a))

        with pytest.raises(FridaError) as info:
            client.java_enumerate("usb", 9999, allowed_pids=[100, 200], mode="classes")

        assert info.value.code == "permission_denied"
        assert info.value.details["pid"] == 9999
        assert info.value.details["allowed_pids"] == [100, 200]
        assert resolved == [], "authorization must run before the device is resolved"

    def test_hook_template_device_refuses_a_pid_outside_the_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The second device entry point shares _authorize; pinning it
        separately catches a new device op that forgets the gate."""
        client = _client_with_sentinel_frida()
        resolved: list[object] = []
        monkeypatch.setattr(client, "_resolve_device", lambda *a, **k: resolved.append(a))

        with pytest.raises(FridaError) as info:
            client.hook_template_device("usb", 9999, "jni_trace", allowed_pids=[100])

        assert info.value.code == "permission_denied"
        assert resolved == []

    def test_an_authorized_pid_passes_the_gate_and_reaches_the_device(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The other half: a pid in the set must not be refused. Prove it by
        letting _resolve_device raise a marker -- reaching it means _authorize
        allowed the pid through."""
        client = _client_with_sentinel_frida()

        class _Marker(Exception):
            pass

        def _boom(*_a: object, **_k: object) -> object:
            raise _Marker

        monkeypatch.setattr(client, "_resolve_device", _boom)
        with pytest.raises(_Marker):
            client.java_enumerate("usb", 200, allowed_pids=[100, 200], mode="classes")

    @pytest.mark.parametrize("pid", [0, -1, -(10**9), True])
    def test_a_nonpositive_or_bool_pid_is_invalid_params(self, pid: object) -> None:
        # bool is a subtype of int; `type(pid) is not int` refuses True so it is
        # never read as pid 1 and matched against an authorized 1.
        client = _client_with_sentinel_frida()
        with pytest.raises(FridaError) as info:
            client.java_enumerate("usb", pid, allowed_pids=[1], mode="classes")  # type: ignore[arg-type]
        assert info.value.code == "invalid_params"

    def test_device_path_reports_the_missing_backend_first(self) -> None:
        """_authorize checks availability before the pid set, so with frida
        absent an unauthorized pid reads as capability_unavailable, not
        permission_denied -- the opposite order from the local path below."""
        client = FridaClient()
        client._available = False
        client._frida = None
        with pytest.raises(FridaError) as info:
            client.java_enumerate("usb", 9999, allowed_pids=[100], mode="classes")
        assert info.value.code == "capability_unavailable"


class TestLocalAuthorization:
    def test_require_is_fail_closed_on_authorization_even_with_frida_absent(self) -> None:
        """The local single-pid gate checks the pid mismatch *before*
        availability: an unauthorized pid is refused as permission_denied
        regardless of whether frida is installed, so the authorization decision
        never depends on backend presence. This is the intentional asymmetry
        with the device path, and the security-relevant ordering to hold."""
        client = FridaClient()
        client._available = False
        client._frida = None
        with pytest.raises(FridaError) as info:
            client.modules(999, allowed_pid=100)
        assert info.value.code == "permission_denied"
        assert info.value.details["pid"] == 999

    def test_require_reports_capability_unavailable_for_the_authorized_pid(self) -> None:
        """The matching pid gets past the permission check and then, with frida
        absent, reports the missing backend -- confirming permission is first,
        availability second."""
        client = FridaClient()
        client._available = False
        client._frida = None
        with pytest.raises(FridaError) as info:
            client.modules(100, allowed_pid=100)
        assert info.value.code == "capability_unavailable"
