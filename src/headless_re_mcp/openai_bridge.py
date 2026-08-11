"""Render the protocol-independent tool catalog as OpenAI function-calling tools.

MCP tool names are dotted (``static.functions``) while OpenAI restricts function
names to ``[A-Za-z0-9_-]{1,64}``. This module renders every bound tool into the
OpenAI ``tools[]`` shape and returns the reverse map so a caller can dispatch a
model's ``function_call`` back onto the original MCP/agent tool.

Run ``python -m headless_re_mcp.openai_bridge`` to print the export as JSON.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from headless_re_mcp.tools.catalog import (
    COMMAND_CATALOG,
    CommandCatalog,
    CommandSpec,
    CommandTransport,
)

JsonObject = dict[str, Any]

MAX_FUNCTION_NAME = 64
_ALLOWED_EXTRA = frozenset({"_", "-"})


def openai_function_name(tool_name: str) -> str:
    """Convert a dotted MCP tool name into an OpenAI-safe function name."""
    converted = "".join(
        character if character.isalnum() or character in _ALLOWED_EXTRA else "_"
        for character in tool_name
    )
    trimmed = converted.strip("_") or "tool"
    if len(trimmed) > MAX_FUNCTION_NAME:
        trimmed = trimmed[:MAX_FUNCTION_NAME].rstrip("_")
    return trimmed


def _bound_specs(
    catalog: CommandCatalog,
    transport: CommandTransport,
) -> tuple[CommandSpec, ...]:
    specs = catalog.for_transport(transport)
    unbound = sorted(spec.name for spec in specs if spec.input_schema is None)
    if unbound:
        raise RuntimeError(
            "catalog tools are not bound yet; bind_all_tools must run first: "
            + ", ".join(unbound[:5])
        )
    return specs


def render_openai_tool(spec: CommandSpec) -> JsonObject:
    """Render one bound catalog spec as a single OpenAI tools[] entry."""
    return {
        "type": "function",
        "function": {
            "name": openai_function_name(spec.name),
            "description": spec.description or spec.name,
            "parameters": dict(spec.input_schema or {}),
        },
    }


def build_openai_tools(
    catalog: CommandCatalog | None = None,
    *,
    transport: CommandTransport = CommandTransport.MCP,
) -> JsonObject:
    """Build the full OpenAI export: tools[], reverse name map and effect policy.

    ``name_map`` maps the OpenAI-safe function name back to the MCP tool name.
    ``write_tools`` lists names whose effects mutate state, so a bridge can keep
    the project's approval rules instead of auto-executing everything.
    """
    source = COMMAND_CATALOG if catalog is None else catalog
    specs = _bound_specs(source, transport)

    tools: list[JsonObject] = []
    name_map: dict[str, str] = {}
    for spec in sorted(specs, key=lambda item: item.name):
        function_name = openai_function_name(spec.name)
        previous = name_map.get(function_name)
        if previous is not None:
            raise RuntimeError(
                f"OpenAI function name collision: {previous} and {spec.name} "
                f"both map to {function_name}"
            )
        name_map[function_name] = spec.name
        tools.append(render_openai_tool(spec))

    return {
        "tools": tools,
        "name_map": name_map,
        "count": len(tools),
        "write_tools": sorted(
            openai_function_name(spec.name) for spec in specs if spec.write
        ),
        "transport": transport.value,
    }


def build_bound_catalog() -> CommandCatalog:
    """Bind every tool onto a fresh catalog without starting any transport."""
    from headless_re_mcp.core.service import AnalysisService
    from headless_re_mcp.tools.assembly import bind_all_tools

    analysis = AnalysisService()
    try:
        catalog = CommandCatalog()
        bind_all_tools(analysis, catalog)
    finally:
        analysis.close_all()
    return catalog


def export_openai_tools(output_path: Path | None = None) -> JsonObject:
    """Build the export from a freshly bound catalog, optionally writing JSON."""
    payload = build_openai_tools(build_bound_catalog())
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        payload = {**payload, "output_path": str(output_path)}
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export Headless RE-MCP tools as OpenAI function-calling definitions",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="write the export to this path instead of stdout",
    )
    parser.add_argument(
        "--names-only",
        action="store_true",
        help="print only the OpenAI name -> MCP name map",
    )
    args = parser.parse_args(argv)

    payload = export_openai_tools(args.output)
    if args.names_only:
        payload = {"name_map": payload["name_map"], "count": payload["count"]}
    if args.output is None or args.names_only:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(f"wrote {payload['count']} OpenAI tool definitions to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
