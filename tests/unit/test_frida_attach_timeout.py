"""frida.attach must not wait on a wedged target forever."""

from __future__ import annotations

import time

import pytest

import headless_re_mcp.backends.frida.client as frida_client
from headless_re_mcp.backends.frida.client import FridaClient, FridaError


def test_frida_attach_does_not_wait_forever(monkeypatch: pytest.MonkeyPatch) -> None:
    """frida.attach used to run with no deadline.

    Measured: a 0.8s sleep in attach held frida.attach 0.8s. A wedged
    target pinned the worker. get_usb_device already had a timeout;
    this hop did not.
    """
    monkeypatch.setattr(frida_client, "_ATTACH_TIMEOUT", 0.4)

    class _Sess:
        def detach(self) -> None:
            return None

    class _Fake:
        def attach(self, pid: int) -> _Sess:
            assert pid == 4242
            time.sleep(30)
            return _Sess()

    client = FridaClient()
    client._frida = _Fake()
    client._available = True
    t0 = time.monotonic()
    with pytest.raises(FridaError) as caught:
        client.attach(4242, allowed_pid=4242)
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0
    assert caught.value.code == "timeout"


def test_frida_modules_does_not_wait_on_attach_forever(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """frida.modules used the same unbounded attach hop.

    Measured: a 0.8s sleep in attach held modules 0.8s after
    frida.attach itself was already bounded.
    """
    monkeypatch.setattr(frida_client, "_ATTACH_TIMEOUT", 0.4)

    class _Sess:
        def detach(self) -> None:
            return None

    class _Fake:
        def attach(self, pid: int) -> _Sess:
            time.sleep(30)
            return _Sess()

    client = FridaClient()
    client._frida = _Fake()
    client._available = True
    t0 = time.monotonic()
    with pytest.raises(FridaError) as caught:
        client.modules(4242, allowed_pid=4242)
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0
    assert caught.value.code == "timeout"


def test_frida_exports_does_not_wait_on_attach_forever(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """frida.exports used the same unbounded attach hop.

    Measured: a 0.8s sleep in attach held exports 0.8s after
    frida.attach itself was already bounded.
    """
    monkeypatch.setattr(frida_client, "_ATTACH_TIMEOUT", 0.4)

    class _Sess:
        def detach(self) -> None:
            return None

    class _Fake:
        def attach(self, pid: int) -> _Sess:
            time.sleep(30)
            return _Sess()

    client = FridaClient()
    client._frida = _Fake()
    client._available = True
    t0 = time.monotonic()
    with pytest.raises(FridaError) as caught:
        client.exports(4242, "libc.so", allowed_pid=4242)
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0
    assert caught.value.code == "timeout"


def test_frida_memory_read_does_not_wait_on_attach_forever(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """frida.memory.read used the same unbounded attach hop.

    Measured: a 0.8s sleep in attach held memory_read 0.8s after
    frida.attach itself was already bounded.
    """
    monkeypatch.setattr(frida_client, "_ATTACH_TIMEOUT", 0.4)

    class _Sess:
        def detach(self) -> None:
            return None

    class _Fake:
        def attach(self, pid: int) -> _Sess:
            time.sleep(30)
            return _Sess()

    client = FridaClient()
    client._frida = _Fake()
    client._available = True
    t0 = time.monotonic()
    with pytest.raises(FridaError) as caught:
        client.memory_read(4242, 0x1000, 4, allowed_pid=4242)
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0
    assert caught.value.code == "timeout"


def test_frida_hook_template_does_not_wait_on_attach_forever(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """frida.hook.template used the same unbounded attach hop.

    Measured: a 0.8s sleep in attach held hook_template 0.8s after
    frida.attach itself was already bounded.
    """
    monkeypatch.setattr(frida_client, "_ATTACH_TIMEOUT", 0.4)

    class _Sess:
        def detach(self) -> None:
            return None

    class _Fake:
        def attach(self, pid: int) -> _Sess:
            time.sleep(30)
            return _Sess()

    client = FridaClient()
    client._frida = _Fake()
    client._available = True
    t0 = time.monotonic()
    with pytest.raises(FridaError) as caught:
        client.hook_template(4242, "noop", allowed_pid=4242)
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0
    assert caught.value.code == "timeout"


def test_frida_java_enumerate_does_not_wait_on_attach_forever(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """java_enumerate used device.attach with no deadline.

    Measured: a 0.8s sleep in device.attach held java_enumerate 0.8s.
    get_usb_device already had a timeout; this hop did not.
    """
    monkeypatch.setattr(frida_client, "_ATTACH_TIMEOUT", 0.4)

    class _Dev:
        def attach(self, pid: int) -> object:
            time.sleep(30)
            raise AssertionError("attach must not return after the deadline")

    class _Fake:
        def get_usb_device(self, timeout: object = None) -> _Dev:
            return _Dev()

    client = FridaClient()
    client._frida = _Fake()
    client._available = True
    t0 = time.monotonic()
    with pytest.raises(FridaError) as caught:
        client.java_enumerate("usb", 4242, allowed_pids=[4242], mode="classes")
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0
    assert caught.value.code == "timeout"


def test_frida_device_hook_does_not_wait_on_attach_forever(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """hook_template_device used device.attach with no deadline.

    Measured: a 0.8s sleep in device.attach held hook_template_device
    0.8s after java_enumerate was already bounded.
    """
    monkeypatch.setattr(frida_client, "_ATTACH_TIMEOUT", 0.4)

    class _Dev:
        def attach(self, pid: int) -> object:
            time.sleep(30)
            raise AssertionError("attach must not return after the deadline")

    class _Fake:
        def get_usb_device(self, timeout: object = None) -> _Dev:
            return _Dev()

    client = FridaClient()
    client._frida = _Fake()
    client._available = True
    t0 = time.monotonic()
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 4242, "noop", allowed_pids=[4242])
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0
    assert caught.value.code == "timeout"


def test_frida_spawn_does_not_wait_forever(monkeypatch: pytest.MonkeyPatch) -> None:
    """frida.spawn used device.spawn with no deadline.

    Measured: a 0.8s sleep in spawn held frida.spawn 0.8s.
    get_usb_device already had a timeout; this hop did not.
    """
    monkeypatch.setattr(frida_client, "_SPAWN_TIMEOUT", 0.4)

    class _Dev:
        def spawn(self, args: object) -> int:
            time.sleep(30)
            return 99

        def resume(self, pid: int) -> None:
            raise AssertionError("resume must not run after a spawn timeout")

    class _Fake:
        def get_usb_device(self, timeout: object = None) -> _Dev:
            return _Dev()

    client = FridaClient()
    client._frida = _Fake()
    client._available = True
    t0 = time.monotonic()
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0
    assert caught.value.code == "timeout"


def test_frida_spawn_does_not_wait_on_resume_forever(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """frida.spawn used device.resume with no deadline.

    Measured: a 0.8s sleep in resume held frida.spawn 0.8s after spawn
    itself already returned.
    """
    monkeypatch.setattr(frida_client, "_RESUME_TIMEOUT", 0.4)

    class _Dev:
        def spawn(self, args: object) -> int:
            return 99

        def resume(self, pid: int) -> None:
            time.sleep(30)

    class _Fake:
        def get_usb_device(self, timeout: object = None) -> _Dev:
            return _Dev()

    client = FridaClient()
    client._frida = _Fake()
    client._available = True
    t0 = time.monotonic()
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0
    assert caught.value.code == "timeout"


def test_frida_applications_does_not_wait_forever(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """frida.applications used enumerate_applications with no deadline.

    Measured: a 0.8s sleep in that hop held applications 0.8s.
    """
    monkeypatch.setattr(frida_client, "_APPLICATIONS_TIMEOUT", 0.4)

    class _Dev:
        def enumerate_applications(self) -> list[object]:
            time.sleep(30)
            return []

    class _Fake:
        def get_usb_device(self, timeout: object = None) -> _Dev:
            return _Dev()

    client = FridaClient()
    client._frida = _Fake()
    client._available = True
    t0 = time.monotonic()
    with pytest.raises(FridaError) as caught:
        client.applications("usb")
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0
    assert caught.value.code == "timeout"
