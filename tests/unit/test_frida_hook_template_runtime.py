"""The hook-template load path actually runs, discloses, and always detaches.

The field test for frida.hook.template only inspects the return-dict source, and
the closed-session test swaps the client method out for a fake, so the real
method bodies -- attach, compile the canned template, load it, and detach in a
finally -- were never executed. Those bodies carry the contract that matters
once a hook loads:

* the reply merges ``_PROBE_DISCLOSURE`` (``persisted: False`` plus the note
  that the hook was destroyed when this probe session detached), because these
  templates -- SSL unpin, crypto monitor, root bypass -- are the ones a caller
  most wants to believe stayed active. The probe detaches immediately, which
  tears the script down, so the reply says so rather than reporting a hook that
  stopped existing before the caller read it.
* the session is detached in a finally on every outcome, success or failure, so
  a load that raises does not strand an agent resident in the target.

These run with an injected fake frida module / device -- no target process --
exactly where the load-and-disclose lives.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.frida.client import _HOOK_TEMPLATES, FridaClient, FridaError


class _Script:
    def __init__(self, *, fail_load: bool = False) -> None:
        self._fail_load = fail_load

    def load(self) -> None:
        if self._fail_load:
            raise RuntimeError("template will not compile on this runtime")


class _Session:
    def __init__(self, *, fail_load: bool = False) -> None:
        self.detached = False
        self._fail_load = fail_load
        self.loaded_source: str | None = None

    def create_script(self, source: str) -> _Script:
        self.loaded_source = source
        return _Script(fail_load=self._fail_load)

    def detach(self) -> None:
        self.detached = True


class _LocalFrida:
    def __init__(self, *, fail_load: bool = False) -> None:
        self._fail_load = fail_load
        self.session: _Session | None = None

    def attach(self, pid: int, timeout: float | None = None) -> _Session:
        del pid, timeout
        self.session = _Session(fail_load=self._fail_load)
        return self.session


class _Device:
    def __init__(self, *, fail_load: bool = False) -> None:
        self._fail_load = fail_load
        self.session: _Session | None = None

    def attach(self, pid: int, timeout: float | None = None) -> _Session:
        del pid, timeout
        self.session = _Session(fail_load=self._fail_load)
        return self.session


def test_local_hook_template_loads_discloses_non_persistence_and_detaches() -> None:
    """A loaded local template answers persisted False with the destroy note.

    The reply must carry loaded True beside persisted False and the note --
    reading loaded alone as "the hook is live" is the exact misread the
    disclosure exists to prevent -- and the probe session is torn down.
    """
    frida = _LocalFrida()
    client = FridaClient()
    client._available = True
    client._frida = frida
    payload = client.hook_template(1234, "noop", allowed_pid=1234)
    assert payload["pid"] == 1234
    assert payload["template"] == "noop"
    assert payload["loaded"] is True
    assert payload["device"] == "local"
    assert payload["persisted"] is False
    assert "destroyed" in payload["note"]
    # The canned template really reached create_script, not an empty string.
    assert frida.session is not None
    assert frida.session.loaded_source == _HOOK_TEMPLATES["noop"]
    # The probe detaches immediately -- that is what makes persisted False true.
    assert frida.session.detached is True


def test_local_hook_template_rejects_an_unknown_template_with_the_allowed_set() -> None:
    """A template name that is not canned is invalid_params, listing the choices.

    The templates are a fixed, audited set (arbitrary injected JS is not a
    tool), so an unknown name is refused with the allowed list rather than
    attaching and loading nothing.
    """
    client = FridaClient()
    client._available = True
    client._frida = _LocalFrida()
    with pytest.raises(FridaError) as caught:
        client.hook_template(1234, "arbitrary-js", allowed_pid=1234)
    assert caught.value.code == "invalid_params"
    allowed = caught.value.details.get("allowed")
    assert allowed == sorted(_HOOK_TEMPLATES)
    assert "noop" in allowed


def test_device_hook_template_loads_a_canned_hook_and_names_the_device() -> None:
    """The device variant carries the resolved device id and the disclosure."""
    device = _Device()
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: device  # type: ignore[method-assign]
    payload = client.hook_template_device(
        "usb", 4321, "android_ssl_unpin", allowed_pids={4321}
    )
    assert payload["pid"] == 4321
    assert payload["template"] == "android_ssl_unpin"
    assert payload["loaded"] is True
    assert payload["device"] == "usb"
    assert payload["persisted"] is False
    assert device.session is not None
    assert device.session.loaded_source == _HOOK_TEMPLATES["android_ssl_unpin"]
    assert device.session.detached is True


def test_local_hook_template_that_fails_to_load_is_backend_error_and_still_detaches() -> None:
    """The local variant classifies a load failure the same as the device one.

    A template that will not compile on this runtime is a backend outcome, not a
    fault in this process -- the local modules/exports/read paths and the device
    hook path all report it as backend_error. The local hook path used to re-raise
    the raw frida exception, which the service mints as an internal_error incident
    for a normal condition; it now matches. The probe session is still torn down.
    """
    frida = _LocalFrida(fail_load=True)
    client = FridaClient()
    client._available = True
    client._frida = frida
    with pytest.raises(FridaError) as caught:
        client.hook_template(1234, "noop", allowed_pid=1234)
    assert caught.value.code == "backend_error"
    assert "hook template failed" in caught.value.message
    assert caught.value.details.get("pid") == 1234
    assert caught.value.details.get("template") == "noop"
    assert frida.session is not None
    assert frida.session.detached is True


def test_device_hook_template_that_fails_to_load_is_backend_error_and_still_detaches() -> None:
    """A script that will not load is a backend_error, and the session is freed.

    The load can fail on a non-ART process or an incompatible runtime; that is a
    device outcome, so it is classified as backend_error rather than surfaced
    raw -- and the detach in the finally still runs, so the failure does not
    leave the probe attached to the target.
    """
    device = _Device(fail_load=True)
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: device  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 4321, "noop", allowed_pids={4321})
    assert caught.value.code == "backend_error"
    assert device.session is not None
    assert device.session.detached is True


class _AttachFailsDevice:
    def attach(self, pid: int, timeout: float | None = None) -> _Session:
        del pid, timeout
        raise RuntimeError("target refuses injection")


def test_device_hook_template_attach_failure_is_backend_error_naming_the_pid() -> None:
    """A failed attach is a target outcome, not an internal fault, and leaks nothing.

    Before any session exists, ``device.attach(pid)`` can raise -- the pid exited
    between authorization and attach, or the process refuses injection. The raw
    frida exception must be classified as backend_error carrying the pid, not
    minted as an internal_error incident for a normal device condition. No
    session was opened, so the finally has nothing to detach and there is no
    resident probe to leak.
    """
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _AttachFailsDevice()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 4321, "noop", allowed_pids={4321})
    assert caught.value.code == "backend_error"
    assert "attach failed" in caught.value.message
    assert caught.value.details.get("pid") == 4321
