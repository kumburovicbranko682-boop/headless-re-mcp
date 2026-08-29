"""A non-string session id given to the web backend is a caller fault.

Every ``session_id`` keys the per-session browser map, but the agent and
OpenAI-bridge transports call handlers straight from model arguments with no
pydantic coercion. An unhashable id (list/dict) reached
``self._sessions.get``/``pop``/``in`` and raised ``TypeError: unhashable type``
that the service's ``except BaseException`` filed as an internal_error incident;
a hashable wrong type (an int) missed silently and was misreported as
``invalid_state`` ("web session not open"). Only the methods that pass through
``registry.get`` first were spared -- navigate, console, scripts, network_list,
dom_snapshot, and close reach the backend directly. Both mistakes must earn
``invalid_params``.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import WebBackend, WebError

_BAD_IDS = (["s"], {"s": 1}, ("s", "id"), 123, 1.5, True, None, b"s")


@pytest.fixture
def backend() -> WebBackend:
    return WebBackend()


def _code(exc_info: pytest.ExceptionInfo[WebError]) -> str:
    return exc_info.value.code


@pytest.mark.parametrize("bad", _BAD_IDS)
def test_a_non_string_session_id_is_invalid_params_everywhere(
    backend: WebBackend, tmp_path: Path, bad: Any
) -> None:
    calls: tuple[Callable[[], Any], ...] = (
        lambda: backend.status(bad),
        lambda: backend.close(bad),
        lambda: backend.open(bad, "http://x"),
        lambda: backend.navigate(bad, "http://x"),
        lambda: backend.network_list(bad),
        lambda: backend.console(bad),
        lambda: backend.scripts(bad),
        lambda: backend.dom_snapshot(bad),
        lambda: backend.network_get(bad, "req-1", tmp_path),
        lambda: backend.script_source(bad, "script-1", tmp_path),
        lambda: backend.screenshot(bad, tmp_path / "s.png"),
        lambda: backend.har_export(bad, tmp_path / "c.har"),
    )
    for call in calls:
        with pytest.raises(WebError) as exc_info:
            call()
        assert _code(exc_info) == "invalid_params"


def test_close_with_an_open_session_present_is_invalid_params_not_a_crash(
    backend: WebBackend,
) -> None:
    """close() uses pop(key, default): empty-dict short-circuits, non-empty hashes.

    CPython's ``dict.pop(k, default)`` skips hashing on an empty dict but hashes
    the key once the dict is populated, so an unhashable id only crashed close()
    when a session was actually open -- exactly when it matters. Any non-empty
    map pins that path; the guard now runs before pop, so the value's shape does
    not matter.
    """
    backend._sessions["real"] = object()  # type: ignore[assignment]
    bad: Any = ["real"]

    with pytest.raises(WebError) as exc_info:
        backend.close(bad)

    assert _code(exc_info) == "invalid_params"


def test_open_names_the_parameter_fault_before_capability(backend: WebBackend) -> None:
    """A malformed request must not be answered with capability_unavailable.

    open() probes for playwright first; with the guard after the probe, an
    environment without playwright blamed the missing dependency for what was
    only a bad argument, sending the operator to install something that was
    never the problem.
    """
    bad: Any = ["s"]
    with pytest.raises(WebError) as exc_info:
        backend.open(bad, "http://x")

    assert _code(exc_info) == "invalid_params"


def test_string_ids_still_reach_the_normal_answers(backend: WebBackend) -> None:
    """The guard must stop only the shapes the schemas forbid."""
    assert backend.status("missing") == {"open": False}
    assert backend.close("missing")["closed"] is False
    with pytest.raises(WebError) as nav_info:
        backend.navigate("missing", "http://x")
    assert _code(nav_info) == "invalid_state"
