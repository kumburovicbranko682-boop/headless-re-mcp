"""A malformed pid must read as invalid_params on every host.

The frida guards used to probe capability (or authorization) before validating
the caller's pid, so ``attach``, the ``_require`` local-device path and the
``_authorize`` device path each returned a *different* code for the very same
malformed pid depending on whether the frida module was importable or whether
the pid happened to match the session's allow-set. Pin the pid shape check as
the first gate in all three so the code a bad pid earns is deterministic.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


def _unavailable_client() -> FridaClient:
    client = FridaClient()
    # Force the "frida not installed" environment regardless of the host: this is
    # exactly where a capability-first guard would mask the invalid_params.
    client._available = False
    client._frida = None
    return client


@pytest.mark.parametrize("bad_pid", [-1, 0, "1234"])
def test_attach_reports_invalid_params_before_capability(bad_pid: object) -> None:
    with pytest.raises(FridaError) as caught:
        _unavailable_client().attach(bad_pid, allowed_pid=1)  # type: ignore[arg-type]
    assert caught.value.code == "invalid_params"


@pytest.mark.parametrize("bad_pid", [-1, 0, "1234"])
def test_local_device_path_reports_invalid_params_before_capability(bad_pid: object) -> None:
    # modules() routes through _require, which used to answer permission_denied
    # (pid != allowed_pid) for a malformed pid before it ever reached capability.
    with pytest.raises(FridaError) as caught:
        _unavailable_client().modules(bad_pid, allowed_pid=1)  # type: ignore[arg-type]
    assert caught.value.code == "invalid_params"


@pytest.mark.parametrize("bad_pid", [-1, 0, "1234"])
def test_device_path_reports_invalid_params_before_capability(bad_pid: object) -> None:
    with pytest.raises(FridaError) as caught:
        _unavailable_client().java_enumerate(
            None, bad_pid, allowed_pids={1}, mode="classes"  # type: ignore[arg-type]
        )
    assert caught.value.code == "invalid_params"


@pytest.mark.parametrize("bad_template", ["arbitrary-script", "definitely-not-a-template", ""])
def test_hook_template_unknown_name_is_invalid_params_without_frida(bad_template: str) -> None:
    # The template name is a fixed, public allow-set checked before the guard, so
    # an unknown template is invalid_params even where frida is not installed.
    with pytest.raises(FridaError) as caught:
        _unavailable_client().hook_template(5, bad_template, allowed_pid=5)
    assert caught.value.code == "invalid_params"


@pytest.mark.parametrize("bad_template", ["arbitrary-script", "definitely-not-a-template", ""])
def test_hook_template_device_unknown_name_is_invalid_params_without_frida(
    bad_template: str,
) -> None:
    with pytest.raises(FridaError) as caught:
        _unavailable_client().hook_template_device("usb", 5, bad_template, allowed_pids={5})
    assert caught.value.code == "invalid_params"


def test_attach_reports_permission_denied_before_capability() -> None:
    # attach is a local-device guard alongside _require, so an unauthorized but
    # well-formed pid is permission_denied even where frida is not installed,
    # matching modules()/_require rather than drifting to capability_unavailable.
    with pytest.raises(FridaError) as caught:
        _unavailable_client().attach(5, allowed_pid=6)
    assert caught.value.code == "permission_denied"


def test_authorize_reports_permission_denied_before_capability() -> None:
    # _authorize checks the allow-set before it probes for frida (matching
    # _require), so an unauthorized but well-formed pid is permission_denied even
    # where frida is not installed -- and never learns the module is absent.
    client = _unavailable_client()
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 4242, allowed_pids={1, 2, 3}, mode="classes")
    assert caught.value.code == "permission_denied"

    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 99, "noop", allowed_pids={7})
    assert caught.value.code == "permission_denied"


def test_malformed_pid_beats_permission_denied_in_require() -> None:
    # Even with frida "available" and the pid outside the allow-set, a malformed
    # pid is the caller's shape error, not a permission decision, so _require must
    # answer invalid_params rather than permission_denied.
    client = FridaClient()
    client._available = True
    client._frida = object()
    with pytest.raises(FridaError) as caught:
        client.modules(-1, allowed_pid=999)
    assert caught.value.code == "invalid_params"
