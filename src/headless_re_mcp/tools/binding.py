"""Protocol-independent typed tool bindings.

Domain modules build these bindings without importing FastMCP, FastAPI, or any
other transport.  Transport adapters may then expose the same typed handlers
while the shared catalog remains the policy and metadata authority.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from pydantic import create_model

HandlerT = TypeVar("HandlerT", bound=Callable[..., dict[str, Any]])


@dataclass(frozen=True, slots=True)
class BoundTool:
    """One canonical tool name bound to its typed application handler."""

    name: str
    handler: Callable[..., dict[str, Any]]


def input_schema_for(handler: Callable[..., dict[str, Any]]) -> dict[str, Any]:
    """Generate the canonical JSON input schema without a transport dependency."""

    signature = inspect.signature(handler, eval_str=True)
    fields: dict[str, Any] = {}
    for parameter in signature.parameters.values():
        annotation = (
            parameter.annotation
            if parameter.annotation is not inspect.Parameter.empty
            else object
        )
        default = (
            parameter.default
            if parameter.default is not inspect.Parameter.empty
            else ...
        )
        fields[parameter.name] = (annotation, default)
    arguments_model = create_model(f"{handler.__name__}Arguments", **fields)
    return dict(arguments_model.model_json_schema(by_alias=True))


class ToolSetBuilder:
    """Collect typed handlers inside a protocol-independent domain factory."""

    def __init__(self) -> None:
        self._bindings: list[BoundTool] = []
        self._names: set[str] = set()

    def tool(self, *, name: str) -> Callable[[HandlerT], HandlerT]:
        def decorate(handler: HandlerT) -> HandlerT:
            if name in self._names:
                raise ValueError(f"duplicate tool binding: {name}")
            self._names.add(name)
            self._bindings.append(BoundTool(name, handler))
            return handler

        return decorate

    @property
    def bindings(self) -> tuple[BoundTool, ...]:
        return tuple(self._bindings)
