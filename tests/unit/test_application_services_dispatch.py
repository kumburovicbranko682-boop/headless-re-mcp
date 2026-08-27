"""Each application service forwards ``call`` to the façade unchanged.

``AnalysisService`` exposes its domain surfaces through ``services.runtime``,
``services.dynamic``, ``services.interaction`` and ``services.artifacts``. Each
carries a ``call(operation, ...)`` escape hatch so a consumer holding only the
domain service can reach a façade method that has no dedicated wrapper yet.
The contract worth pinning is that dispatch is verbatim: the named operation is
looked up on the façade and receives exactly the positional and keyword
arguments the caller passed, and an unknown operation surfaces as the ordinary
AttributeError rather than being swallowed into a None.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.core.application_services import (
    ArtifactApplicationService,
    DynamicApplicationService,
    InteractionApplicationService,
    RuntimeApplicationService,
)


def _services(facade: Any) -> list[Any]:
    return [
        RuntimeApplicationService(facade=facade, state=SimpleNamespace()),
        DynamicApplicationService(facade=facade, debuggee=SimpleNamespace()),
        InteractionApplicationService(facade=facade),
        ArtifactApplicationService(facade=facade, repository=SimpleNamespace()),
    ]


def test_call_forwards_the_operation_and_its_arguments_verbatim() -> None:
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def probe(*args: Any, **kwargs: Any) -> str:
        calls.append((args, kwargs))
        return "answered"

    facade = SimpleNamespace(probe=probe)

    for service in _services(facade):
        assert service.call("probe", "sess-1", limit=5) == "answered"

    assert calls == [(("sess-1",), {"limit": 5})] * 4


def test_call_lets_an_unknown_operation_fail_loud() -> None:
    """A typo in an operation name must not degrade into a silent no-op."""
    for service in _services(SimpleNamespace()):
        with pytest.raises(AttributeError, match="no_such_op"):
            service.call("no_such_op")
