"""The device-path authorization gate and fault mapping, with fakes.

The Android dynamic-analysis methods -- java_enumerate and hook_template_device
-- share an authorization gate (_authorize) and a work() body that attaches,
loads a fixed script, runs an RPC, and detaches in a finally. The happy paths
and the permission_denied boundary are covered elsewhere (test_android_backends,
test_frida_java_input_bounds), but the degradation branches only ran with the
real frida module installed, so on this box the real-client tests for them skip.
These inject fakes (the established `client._available = True; client._frida =
...` seam) to pin, deterministically, the branches an unattended agent actually
hits when a device misbehaves: the capability gate when frida is absent, a
non-positive pid refused as invalid_params before any device work, an attach or
an RPC fault mapped to a precise backend_error (never a leaked exception), the
tolerant bare-array methods shape from an older script, and the hook template
allow-list refusal.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


class _Script:
    def __init__(self, api: Any) -> None:
        self.exports_sync = api

    def load(self) -> None:
        return None


class _Session:
    def __init__(self, api: Any) -> None:
        self._api = api
        self.detached = False

    def create_script(self, source: str) -> _Script:
        assert source
        return _Script(self._api)

    def detach(self) -> None:
        self.detached = True


class _Device:
    """A device whose attach either yields a session over ``api`` or raises."""

    def __init__(self, *, api: Any = None, attach_error: BaseException | None = None) -> None:
        self._api = api
        self._attach_error = attach_error
        self.session: _Session | None = None

    def attach(self, pid: int) -> _Session:
        if self._attach_error is not None:
            raise self._attach_error
        self.session = _Session(self._api)
        return self.session


def _client(device: _Device | None) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = object()
    if device is not None:
        client._resolve_device = lambda device_id: device  # type: ignore[method-assign]
    else:
        # No device should be reached; if resolution runs, the guard under test
        # failed to fail fast.
        def _forbidden(device_id: str | None) -> Any:
            raise AssertionError("device was resolved before the guard refused the call")

        client._resolve_device = _forbidden  # type: ignore[method-assign]
    return client


def test_java_enumerate_without_frida_reports_capability_unavailable() -> None:
    """_authorize gates on the module first: a session that somehow reaches a
    device tool without frida installed gets capability_unavailable, not a later,
    more confusing failure. Forced deterministically rather than skipped."""
    client = FridaClient()
    client._available = False
    client._frida = None
    with pytest.raises(FridaError) as caught:
        client.java_enumerate("usb", 1, allowed_pids={1}, mode="classes")
    assert caught.value.code == "capability_unavailable"


@pytest.mark.parametrize("bad_pid", [0, -1, -4242, 1.5, "1"])
def test_java_enumerate_refuses_a_non_positive_or_non_int_pid(bad_pid: Any) -> None:
    """The tool schema bounds pid ge=0 (0 = 'last spawned'), but the service maps
    0 to a real pid before the client sees it, so at the client a pid must be a
    positive int. A bypassing transport handing 0, a negative, or a non-int is
    refused as invalid_params before any device is resolved -- the authorization
    set is only consulted for a well-formed pid."""
    client = _client(None)
    with pytest.raises(FridaError) as caught:
        client.java_enumerate("usb", bad_pid, allowed_pids={1}, mode="classes")
    assert caught.value.code == "invalid_params"
    assert "positive integer" in caught.value.message


def test_java_enumerate_maps_an_attach_failure_to_backend_error() -> None:
    """A device that refuses the attach must surface backend_error carrying the
    pid, not the raw frida exception -- and the session is never created."""
    device = _Device(attach_error=RuntimeError("device is busy"))
    client = _client(device)
    with pytest.raises(FridaError) as caught:
        client.java_enumerate("usb", 4242, allowed_pids={4242}, mode="classes")
    assert caught.value.code == "backend_error"
    assert caught.value.details.get("pid") == 4242
    assert "attach failed" in caught.value.message


def test_java_enumerate_maps_an_rpc_fault_to_backend_error_and_detaches() -> None:
    """When the enumeration RPC itself blows up, the outer guard maps it to
    backend_error and the finally still detaches the session -- a failed call
    must not leave an agent resident in the target."""

    class _FaultApi:
        def classes(self, name_filter: str, count: int) -> list[str]:
            raise RuntimeError("script rpc crashed")

    device = _Device(api=_FaultApi())
    client = _client(device)
    with pytest.raises(FridaError) as caught:
        client.java_enumerate("usb", 4242, allowed_pids={4242}, mode="classes")
    assert caught.value.code == "backend_error"
    assert "java enumeration failed" in caught.value.message
    assert device.session is not None and device.session.detached is True


def test_java_enumerate_tolerates_the_bare_array_methods_shape() -> None:
    """An older script returns methods as a bare list rather than {found, methods}.
    The client must treat that as found=True with the list paged, matching how
    modules tolerates the same older shape -- not crash on the missing dict."""

    class _BareArrayApi:
        def methods(self, class_name: str, count: int) -> list[str]:
            return ["<init>", "toString", "hashCode"]

    device = _Device(api=_BareArrayApi())
    client = _client(device)
    payload = client.java_enumerate(
        "usb", 4242, allowed_pids={4242}, mode="methods", class_name="com.example.Foo", limit=50
    )
    assert payload["found"] is True
    assert payload["methods"] == ["<init>", "toString", "hashCode"]
    assert payload["count"] == 3
    assert payload["has_more"] is False


def test_hook_template_device_refuses_an_unknown_template_before_device_work() -> None:
    """The template allow-list is a fixed set; an unknown name is invalid_params
    with the allowed names disclosed, and no device is resolved for it."""
    client = _client(None)
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 4242, "arbitrary-script", allowed_pids={4242})
    assert caught.value.code == "invalid_params"
    assert "android_ssl_unpin" in caught.value.details.get("allowed", [])


def test_hook_template_device_maps_an_attach_failure_to_backend_error() -> None:
    """A device that refuses the attach on a known template maps to backend_error
    carrying the pid, the same taxonomy the enumeration path uses."""
    device = _Device(attach_error=RuntimeError("no such process"))
    client = _client(device)
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 4242, "noop", allowed_pids={4242})
    assert caught.value.code == "backend_error"
    assert caught.value.details.get("pid") == 4242
    assert "attach failed" in caught.value.message


def test_hook_template_device_maps_a_script_load_fault_to_backend_error() -> None:
    """Attach can succeed and the script still fail to compile/load. That fault
    escapes work() past the attach guard, so the outer guard maps it to a
    distinct backend_error ('hook template failed'), and the finally detaches --
    a failed load must not leave the session (and any partial script) resident."""

    class _BadScript:
        exports_sync = object()

        def load(self) -> None:
            raise RuntimeError("script failed to compile")

    class _BadSession:
        def __init__(self) -> None:
            self.detached = False

        def create_script(self, source: str) -> _BadScript:
            assert source
            return _BadScript()

        def detach(self) -> None:
            self.detached = True

    class _Dev:
        def __init__(self) -> None:
            self.session = _BadSession()

        def attach(self, pid: int) -> _BadSession:
            return self.session

    device = _Dev()
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: device  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 4242, "noop", allowed_pids={4242})
    assert caught.value.code == "backend_error"
    assert "hook template failed" in caught.value.message
    assert device.session.detached is True


def test_java_enumerate_reports_a_synchronous_frida_timeout_as_timeout() -> None:
    """A timeout stays a timeout regardless of who raised it. The daemon-thread
    wall-clock path already yields the timeout envelope; this pins the other
    source -- frida raising its own timeout-shaped exception synchronously -- so
    the client maps it to code 'timeout', not the generic backend_error a bare
    exception would otherwise become."""
    device = _Device(attach_error=RuntimeError("frida: operation timed out"))
    client = _client(device)
    with pytest.raises(FridaError) as caught:
        client.java_enumerate("usb", 4242, allowed_pids={4242}, mode="classes")
    assert caught.value.code == "timeout"


def test_java_enumerate_reports_an_rpc_timeout_as_timeout_and_detaches() -> None:
    """The enumeration RPC (not just the attach) timing out is a timeout too.

    An RPC fault escapes past the inner attach guard to the outer handler, which
    the plain-fault test proves becomes backend_error. This pins the other outer
    branch: a timeout-shaped RPC fault maps to 'timeout', and the finally still
    detaches -- a wedged enumeration must not leave the agent resident."""

    class _SlowApi:
        def classes(self, name_filter: str, count: int) -> list[str]:
            raise RuntimeError("frida: rpc timed out")

    device = _Device(api=_SlowApi())
    client = _client(device)
    with pytest.raises(FridaError) as caught:
        client.java_enumerate("usb", 4242, allowed_pids={4242}, mode="classes")
    assert caught.value.code == "timeout"
    assert device.session is not None and device.session.detached is True


def test_hook_template_device_reports_a_synchronous_attach_timeout_as_timeout() -> None:
    """hook_template_device's attach timing out synchronously is a timeout, the
    same source java_enumerate pins -- not the backend_error a bare fault gives."""
    device = _Device(attach_error=RuntimeError("frida: attach timed out"))
    client = _client(device)
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 4242, "noop", allowed_pids={4242})
    assert caught.value.code == "timeout"


def test_hook_template_device_reports_a_script_load_timeout_as_timeout_and_detaches() -> None:
    """A script load that times out (not merely fails) is a timeout at the outer
    handler, and the finally still detaches -- the timeout counterpart of the
    script-load backend_error case, so a wedged load leaves no resident session."""

    class _SlowScript:
        exports_sync = object()

        def load(self) -> None:
            raise RuntimeError("frida: script load timed out")

    class _SlowSession:
        def __init__(self) -> None:
            self.detached = False

        def create_script(self, source: str) -> _SlowScript:
            assert source
            return _SlowScript()

        def detach(self) -> None:
            self.detached = True

    class _Dev:
        def __init__(self) -> None:
            self.session = _SlowSession()

        def attach(self, pid: int) -> _SlowSession:
            return self.session

    device = _Dev()
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: device  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 4242, "noop", allowed_pids={4242})
    assert caught.value.code == "timeout"
    assert device.session.detached is True
