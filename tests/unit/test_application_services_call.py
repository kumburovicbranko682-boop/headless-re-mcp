"""Coverage for the application-service delegation shims.

The typed methods on each application service are covered by the façade tests.
These pin the generic ``call(operation, *args, **kwargs)`` shims on all four
services, which forward by name to the underlying façade.
"""

from __future__ import annotations

from typing import Any, cast

from headless_re_mcp.core.application_services import (
    ArtifactApplicationService,
    DynamicApplicationService,
    InteractionApplicationService,
    RuntimeApplicationService,
    ServicePort,
)
from headless_re_mcp.core.repository import AnalysisRepository
from headless_re_mcp.core.runtime_state import BackendRuntimeOwner, DebuggeeStateOwner


class _Facade:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def do_thing(self, *args: Any, **kwargs: Any) -> str:
        self.calls.append((args, kwargs))
        return "delegated"


def _port(facade: _Facade) -> ServicePort:
    return cast(ServicePort, facade)


def test_runtime_service_call_forwards_to_the_facade_by_name() -> None:
    facade = _Facade()
    service = RuntimeApplicationService(
        facade=_port(facade), state=cast(BackendRuntimeOwner[Any], object())
    )
    assert service.call("do_thing", 1, x=2) == "delegated"
    assert facade.calls == [((1,), {"x": 2})]


def test_dynamic_service_call_forwards_to_the_facade_by_name() -> None:
    facade = _Facade()
    service = DynamicApplicationService(
        facade=_port(facade), debuggee=cast(DebuggeeStateOwner, object())
    )
    assert service.call("do_thing", "a") == "delegated"
    assert facade.calls == [(("a",), {})]


def test_interaction_service_call_forwards_to_the_facade_by_name() -> None:
    facade = _Facade()
    service = InteractionApplicationService(facade=_port(facade))
    assert service.call("do_thing", key="value") == "delegated"
    assert facade.calls == [((), {"key": "value"})]


def test_artifact_service_call_forwards_to_the_facade_by_name() -> None:
    facade = _Facade()
    service = ArtifactApplicationService(
        facade=_port(facade), repository=cast(AnalysisRepository, object())
    )
    assert service.call("do_thing") == "delegated"
    assert facade.calls == [((), {})]
