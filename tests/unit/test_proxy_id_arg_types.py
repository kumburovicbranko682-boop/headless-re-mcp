"""A non-string session or flow id given to the proxy backend is a caller fault.

Every id keys a plain dict (the instance map, the recorder's raw-flow map), but
the agent and OpenAI-bridge transports call handlers straight from model
arguments with no pydantic coercion. An unhashable id (list/dict) reached
``dict.get``/``dict.pop``/``in`` and raised ``TypeError: unhashable type`` that
the service's ``except BaseException`` filed as an internal_error incident; a
hashable wrong type (an int) missed silently and was misreported as "no proxy
running". Both are the same parameter mistake and must earn invalid_params.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.proxy.client import ProxyBackend, ProxyError, _ProxyInstance

_BAD_IDS = (["sid"], {"sid": 1}, ("s", "id"), 123, 1.5, True, None, b"sid")


@pytest.fixture
def backend() -> ProxyBackend:
    return ProxyBackend()


def _registered(backend: ProxyBackend, session_id: str = "sid") -> None:
    # A registered-but-never-started instance: the recorder and its raw-flow
    # map exist without mitmproxy, which is exactly where flow_id lands.
    backend._instances[session_id] = _ProxyInstance("127.0.0.1", 18080)


def _code(exc_info: pytest.ExceptionInfo[ProxyError]) -> str:
    return exc_info.value.code


@pytest.mark.parametrize("bad", _BAD_IDS)
def test_a_non_string_session_id_is_invalid_params_everywhere(
    backend: ProxyBackend, tmp_path: Path, bad: Any
) -> None:
    calls: tuple[Callable[[], Any], ...] = (
        lambda: backend.start(bad),
        lambda: backend.stop(bad),
        lambda: backend.status(bad),
        lambda: backend.flows(bad),
        lambda: backend.flow_get(bad, "flow-1", tmp_path),
        lambda: backend.replay(bad, "flow-1"),
        lambda: backend.export_har(bad, tmp_path / "capture.har"),
    )
    for call in calls:
        with pytest.raises(ProxyError) as exc_info:
            call()
        assert _code(exc_info) == "invalid_params"


@pytest.mark.parametrize("bad", _BAD_IDS)
def test_a_non_string_flow_id_is_invalid_params_not_a_crash(
    backend: ProxyBackend, tmp_path: Path, bad: Any
) -> None:
    _registered(backend)

    with pytest.raises(ProxyError) as get_info:
        backend.flow_get("sid", bad, tmp_path)
    with pytest.raises(ProxyError) as replay_info:
        backend.replay("sid", bad)

    assert _code(get_info) == "invalid_params"
    assert _code(replay_info) == "invalid_params"


def test_start_names_the_parameter_fault_before_capability(backend: ProxyBackend) -> None:
    """A malformed request must not be answered with capability_unavailable.

    start() probes for mitmproxy first; with the guard after the probe, an
    environment without mitmproxy blamed the missing dependency for what was
    only a bad argument, sending the operator to install something that was
    never the problem.
    """
    bad: Any = ["sid"]
    with pytest.raises(ProxyError) as exc_info:
        backend.start(bad)

    assert _code(exc_info) == "invalid_params"


def test_string_ids_still_reach_the_normal_answers(backend: ProxyBackend, tmp_path: Path) -> None:
    """The guard must stop only the shapes the schemas forbid."""
    assert backend.status("missing") == {"running": False}
    assert backend.stop("missing")["stopped"] is False
    with pytest.raises(ProxyError) as flows_info:
        backend.flows("missing")
    assert _code(flows_info) == "invalid_state"

    _registered(backend)
    with pytest.raises(ProxyError) as get_info:
        backend.flow_get("sid", "flow-404", tmp_path)
    assert _code(get_info) == "not_found"
