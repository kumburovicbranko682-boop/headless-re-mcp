"""frida.modules / frida.exports: the payload shapes the fixtures never send.

``frida.modules`` accepts two script return shapes:

    if isinstance(raw, dict):
        held = list(raw.get("modules") or [])
        total = int(raw.get("total") or len(held))
    else:
        held = list(raw or [])
        total = len(held)

The one existing test drives the *list* shape, where ``total`` is forced to
``len(held)`` and ``has_more`` can only mean "the client capped the page". The
*dict* shape is the interesting one: the in-process script can report a
server-side ``total`` larger than the page it returned, so ``has_more`` becomes
"there are more modules than this page holds even after the client's own cut".
With only the list fixture, dropping the dict handling entirely (``list()`` of a
dict yields its *keys*) or collapsing ``total`` to ``len(held)`` would pass.

``frida.exports`` is only ever driven with ``found: True``, the module name
present, and a dict payload. That leaves ``found`` (does the module exist at
all, vs. exists-but-exports-nothing), the module-name fallback, the non-dict
guard, and the name validation all inert.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


class _ModuleApi:
    def __init__(self, result: Any) -> None:
        self._result = result
        self.seen_limit: int | None = None

    def modules(self, limit: int) -> Any:
        self.seen_limit = limit
        return self._result


class _ExportApi:
    def __init__(self, result: Any) -> None:
        self._result = result
        self.seen: tuple[str, int] | None = None

    def exports(self, name: str, count: int) -> Any:
        self.seen = (name, count)
        return self._result


class _Script:
    def __init__(self, api: Any) -> None:
        self.exports_sync = api

    def load(self) -> None:
        return None


class _Session:
    def __init__(self, api: Any) -> None:
        self._api = api

    def create_script(self, source: str) -> _Script:
        del source
        return _Script(self._api)

    def detach(self) -> None:
        return None


class _Frida:
    def __init__(self, api: Any) -> None:
        self._api = api
        self.attach_calls = 0

    def attach(self, pid: int) -> _Session:
        del pid
        self.attach_calls += 1
        return _Session(self._api)


def _client(api: Any) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = _Frida(api)
    return client


def _module(name: str) -> dict[str, Any]:
    return {"name": name, "base": "0x1000", "size": 16, "path": f"/system/lib/{name}"}


# --------------------------------------------------------------------------
# frida.modules -- the dict shape with a server-side total
# --------------------------------------------------------------------------


def test_a_server_side_total_beyond_the_page_still_flags_has_more() -> None:
    """The script returned five modules but reports 200 exist. total must be the
    reported 200 and has_more True -- even though the five-item page was not
    itself capped by the client. The list-shape fixture can never show this: it
    forces total to the page length.
    """
    api = _ModuleApi({"modules": [_module(f"m{i}") for i in range(5)], "total": 200})
    payload = _client(api).modules(1, allowed_pid=1, limit=10)

    assert payload["count"] == 5
    assert payload["total"] == 200
    assert payload["has_more"] is True


def test_a_dict_payload_without_a_total_falls_back_to_the_page_length() -> None:
    """A dict that omits total (or reports 0) falls back to len(held), so a
    complete small page is not falsely flagged has_more.
    """
    api = _ModuleApi({"modules": [_module(f"m{i}") for i in range(3)]})
    payload = _client(api).modules(1, allowed_pid=1, limit=10)

    assert payload["count"] == 3
    assert payload["total"] == 3
    assert payload["has_more"] is False


def test_the_client_recaps_a_dict_page_larger_than_the_limit() -> None:
    """If the script over-returns (20 modules for a limit of 10), the client's
    own held[:capped] slice must still cut the page to the limit, and has_more
    reflects the real total.
    """
    api = _ModuleApi({"modules": [_module(f"m{i}") for i in range(20)], "total": 20})
    payload = _client(api).modules(1, allowed_pid=1, limit=10)

    assert payload["count"] == 10
    assert len(payload["modules"]) == 10
    assert payload["total"] == 20
    assert payload["has_more"] is True


def test_a_non_dict_module_entry_is_skipped_not_indexed_into() -> None:
    """A malformed entry (a bare string where a dict is expected) must be
    filtered by the isinstance guard, not crash on ``.get``. The two real
    modules survive; the reported total is untouched.
    """
    api = _ModuleApi({"modules": [_module("a"), "junk", _module("b")], "total": 3})
    payload = _client(api).modules(1, allowed_pid=1, limit=10)

    assert [m["name"] for m in payload["modules"]] == ["a", "b"]
    assert payload["count"] == 2
    assert payload["total"] == 3


# --------------------------------------------------------------------------
# frida.exports -- found tri-state, fallback, guards, validation
# --------------------------------------------------------------------------


def test_a_missing_module_reports_found_false_with_no_exports() -> None:
    """A module the process never loaded: found False, no exports. This must be
    distinguishable from a loaded module that simply exports nothing.
    """
    api = _ExportApi({"found": False, "module": "nope.so", "base": "", "exports": []})
    payload = _client(api).exports(1, "nope.so", allowed_pid=1, limit=10)

    assert payload["found"] is False
    assert payload["count"] == 0
    assert payload["has_more"] is False


def test_a_loaded_module_with_no_exports_is_found_true_not_false() -> None:
    """found tracks the script's own found flag, not len(exports). A loaded
    module that exports nothing is found True with an empty table -- the
    complement of the missing-module case, and the pair pins found to
    bool(raw["found"]).
    """
    api = _ExportApi({"found": True, "module": "empty.so", "base": "0x1", "exports": []})
    payload = _client(api).exports(1, "empty.so", allowed_pid=1, limit=10)

    assert payload["found"] is True
    assert payload["count"] == 0


def test_a_payload_without_a_module_name_falls_back_to_the_requested_name() -> None:
    """When the script omits the module field, the response echoes the requested
    name rather than an empty string, so the caller can still tell which module
    the table belongs to.
    """
    api = _ExportApi({"found": True, "base": "0x1", "exports": []})
    payload = _client(api).exports(1, "libc.so", allowed_pid=1, limit=10)

    assert payload["module"] == "libc.so"


def test_a_non_dict_exports_payload_is_a_backend_error() -> None:
    """A script that returns a bare list (or anything but the {found, exports}
    object) is a backend fault, mapped to backend_error -- not silently paged
    into an empty table.
    """
    api = _ExportApi(["not", "a", "dict"])
    with pytest.raises(FridaError) as caught:
        _client(api).exports(1, "x.so", allowed_pid=1, limit=10)

    assert caught.value.code == "backend_error"


def test_a_blank_module_name_is_rejected_before_the_process_is_touched() -> None:
    """An empty/whitespace module name is invalid_params, and the rejection
    happens before any attach -- a bad argument must not spin up a frida session
    on the target.
    """
    api = _ExportApi({"found": True, "module": "x", "exports": []})
    client = _client(api)

    with pytest.raises(FridaError) as caught:
        client.exports(1, "   ", allowed_pid=1, limit=10)

    assert caught.value.code == "invalid_params"
    assert client._frida.attach_calls == 0
