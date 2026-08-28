"""Frida enumerations clamp a caller limit at the backend boundary.

``modules`` (256), ``exports`` (512) and ``java_enumerate`` (2000) each shape
the requested page with ``max(1, min(int(limit), CEILING))``. The schema
declares a positive, bounded limit, but the agent and OpenAI-bridge transports
invoke these handlers straight from model arguments with no schema enforcement
-- the same gap that motivated the web ``scripts``/``console`` clamps and the
frida ``applications`` floor. Every existing frida enumeration test passes a
small positive limit, so neither the floor nor the ceiling is ever observed:
drop the ``max(1, ...)`` and a ``limit=0`` still passes (it just requests zero
rows and returns an empty page that misreports ``has_more``); drop the ceiling
and a ``limit=10**9`` still passes while asking the injected script to
enumerate a billion rows in the target.

These pin the clamp by capturing the count the backend actually asks the RPC
for: a non-positive limit floors to one, and an oversized limit is capped at
each method's own ceiling. ``applications`` already has its own regression, so
it is not repeated here.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaClient


class _Api:
    def __init__(self, **methods: Any) -> None:
        for name, fn in methods.items():
            setattr(self, name, fn)


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
        del source
        return _Script(self._api)

    def detach(self) -> None:
        self.detached = True


class _LocalFrida:
    def __init__(self, session: _Session) -> None:
        self._session = session

    def attach(self, pid: int) -> _Session:
        del pid
        return self._session


class _Device:
    def __init__(self, session: _Session) -> None:
        self._session = session

    def attach(self, pid: int) -> _Session:
        del pid
        return self._session


def _local_client(api: _Api) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = _LocalFrida(_Session(api))
    return client


def _device_client(api: _Api) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _Device(_Session(api))  # type: ignore[method-assign]
    return client


# --- modules: exports_sync.modules(capped) -----------------------------------


@pytest.mark.parametrize(
    ("limit", "expected_cap"),
    [(0, 1), (-5, 1), (10**9, 256), (256, 256), (257, 256)],
)
def test_modules_clamps_the_requested_page(limit: int, expected_cap: int) -> None:
    seen: list[int] = []

    def modules(cap: int) -> dict[str, Any]:
        seen.append(cap)
        return {"modules": [], "total": 0}

    _local_client(_Api(modules=modules)).modules(1, allowed_pid=1, limit=limit)
    assert seen == [expected_cap]


# --- exports: exports_sync.exports(name, capped + 1) -------------------------


@pytest.mark.parametrize(
    ("limit", "expected_request"),
    [(0, 2), (-5, 2), (10**9, 513), (512, 513), (513, 513)],
)
def test_exports_clamps_the_requested_page(limit: int, expected_request: int) -> None:
    seen: list[int] = []

    def exports(name: str, count: int) -> dict[str, Any]:
        del name
        seen.append(count)
        return {"found": True, "module": "libc.so", "base": "0x0", "exports": []}

    _local_client(_Api(exports=exports)).exports(1, "libc.so", allowed_pid=1, limit=limit)
    # exports asks for one past the page to detect has_more, so the request is
    # the clamped page plus one.
    assert seen == [expected_request]


# --- java_enumerate classes: exports_sync.classes(filter, capped + 1) --------


@pytest.mark.parametrize(
    ("limit", "expected_request"),
    [(0, 2), (-5, 2), (10**9, 2001), (2000, 2001), (2001, 2001)],
)
def test_java_enumerate_classes_clamps_the_requested_page(
    limit: int, expected_request: int
) -> None:
    seen: list[int] = []

    def classes(name_filter: str, count: int) -> list[str]:
        del name_filter
        seen.append(count)
        return []

    _device_client(_Api(classes=classes)).java_enumerate(
        None, 1, allowed_pids={1}, mode="classes", limit=limit
    )
    assert seen == [expected_request]
