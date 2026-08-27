"""frida.applications: pid derivation and the limit floor.

The existing frida.applications test builds every app with ``pid = 0`` and never
asserts on the pid field -- so the derivation ``int(getattr(app, "pid", 0) or 0)``
is inert. A homogeneous all-zero fixture cannot tell a real running pid passing
through from a hardcoded zero, cannot exercise the ``getattr`` default for an app
that never carried a pid attribute, and cannot exercise the ``or 0`` arm for an
app whose pid is ``None``. Frida reports a live pid for a *running* application
and 0 for a stopped one, so which of those an agent sees is load-bearing. The
same test also asks for a positive limit only, leaving the ``max(1, ...)`` floor
that keeps a non-positive limit from silently returning an empty page unpinned.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.backends.frida.client import FridaClient


class _App:
    def __init__(self, identifier: str, name: str, **kwargs: Any) -> None:
        self.identifier = identifier
        self.name = name
        if "pid" in kwargs:
            self.pid = kwargs["pid"]


class _Device:
    def __init__(self, apps: list[_App]) -> None:
        self._apps = apps

    def enumerate_applications(self) -> list[_App]:
        return self._apps


def _backend(apps: list[_App]) -> FridaClient:
    client = FridaClient()
    client._resolve_device = lambda device_id: _Device(apps)  # type: ignore[method-assign]
    return client


def test_a_running_apps_pid_passes_through_while_a_stopped_app_reads_zero() -> None:
    """A live pid must survive as itself; a stopped app's 0 stays 0, as an int.

    The all-zero fixture could not distinguish a genuine passthrough from a
    constant. Pair a running app (pid 4321) with a stopped one (pid 0) and pin
    both values to their own app.
    """
    client = _backend(
        [_App("com.running", "Running", pid=4321), _App("com.stopped", "Stopped", pid=0)]
    )
    rows = client.applications("usb", limit=10)["applications"]
    apps = {row["identifier"]: row for row in rows}
    assert apps["com.running"]["pid"] == 4321
    assert isinstance(apps["com.running"]["pid"], int)
    assert apps["com.stopped"]["pid"] == 0
    assert isinstance(apps["com.stopped"]["pid"], int)


def test_an_app_missing_its_pid_attribute_reads_zero_not_a_crash() -> None:
    """Some frida builds omit pid entirely on a stopped app. The getattr default
    of 0 must hold; reading ``app.pid`` directly would raise AttributeError and
    fail the whole enumeration.
    """
    client = _backend([_App("com.nopidattr", "NoAttr")])
    row = client.applications("usb", limit=10)["applications"][0]
    assert row["identifier"] == "com.nopidattr"
    assert row["pid"] == 0


def test_an_app_with_a_none_pid_reads_zero_not_a_crash() -> None:
    """A present-but-None pid must fall to 0 via the ``or 0`` arm; ``int(None)``
    would raise TypeError and take the enumeration down with it.
    """
    client = _backend([_App("com.nonepid", "NonePid", pid=None)])
    row = client.applications("usb", limit=10)["applications"][0]
    assert row["identifier"] == "com.nonepid"
    assert row["pid"] == 0


def test_a_non_positive_limit_still_returns_at_least_one_row() -> None:
    """``max(1, min(int(limit), 1000))`` floors the page at one, so a caller who
    passes 0 or a negative limit still sees a row instead of a silently empty
    page. Drop the floor and ``apps[:0]`` yields nothing.
    """
    apps = [_App(f"com.app{i}", f"App{i}", pid=0) for i in range(5)]
    zero = _backend(apps).applications("usb", limit=0)
    assert zero["count"] == 1
    assert len(zero["applications"]) == 1
    assert zero["total"] == 5
    assert zero["has_more"] is True
    negative = _backend(apps).applications("usb", limit=-3)
    assert negative["count"] == 1
    assert len(negative["applications"]) == 1
