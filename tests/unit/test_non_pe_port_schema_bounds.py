"""Every non-PE tool that takes a network `port` must bound it to 1..65535.

Three non-PE operations accept a TCP port from the caller -- ``proxy.start``
(the listen port), ``frida.server.ensure`` (the frida-server listen port) and
``device.connect`` (the adb-over-TCP endpoint port). Each declares the bound in
its tool schema so the MCP path rejects an out-of-range value up front, and each
*also* re-validates in its backend, because the agent and OpenAI-bridge
transports call handlers directly and skip the pydantic schema (only the MCP
path runs it) -- the backend halves are pinned in test_proxy_port_reservation,
test_frida_server_bind_host and test_device_connect_honesty.

This is the schema half, made a drift guard: it scans the whole non-PE tool
surface and fails if any tool exposes a ``port`` parameter that is not an integer
bounded to 1..65535. A new port-bearing tool then cannot ship without a
deliberate decision about its bound, and cannot silently disagree with the
backend checks its siblings enforce.
"""

from __future__ import annotations

from typing import Any, cast

from headless_re_mcp.tools.apk import build_apk_tools
from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.device import build_device_tools
from headless_re_mcp.tools.frida import build_frida_tools
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools
from headless_re_mcp.tools.proxy import build_proxy_tools
from headless_re_mcp.tools.web import build_web_tools
from headless_re_mcp.tools.workspace import build_workspace_tools

# Every builder that makes up the non-PE surface. Each takes the live service
# only so its handlers can close over it; input_schema_for reads the signature
# alone, so a dummy stands in and no backend has to be present.
_NON_PE_BUILDERS = (
    build_web_tools,
    build_proxy_tools,
    build_device_tools,
    build_frida_tools,
    build_apk_tools,
    build_js_wasm_tools,
    build_workspace_tools,
)


def _non_pe_port_properties() -> dict[str, dict[str, Any]]:
    """Map every non-PE tool that declares a ``port`` param to that param schema."""
    found: dict[str, dict[str, Any]] = {}
    for builder in _NON_PE_BUILDERS:
        for bound in builder(cast(Any, object())):
            schema = input_schema_for(bound.handler)
            port = schema.get("properties", {}).get("port")
            if port is not None:
                found[bound.name] = port
    return found


def test_every_non_pe_port_param_is_bounded_1_to_65535() -> None:
    ports = _non_pe_port_properties()

    # The scan must actually see the three known port-bearing tools -- otherwise
    # a broken enumeration would make this guard vacuously pass.
    assert {"proxy.start", "frida.server.ensure", "device.connect"} <= set(ports), (
        f"expected the known port tools in the scan, saw {sorted(ports)}"
    )

    for name, port in ports.items():
        # An integer TCP port: 0 is not a connectable port and 65535 is the max,
        # so the schema must advertise exactly that closed range. A new tool that
        # forgets the bound (a bare int -> no minimum/maximum) trips here.
        assert port.get("type") == "integer", f"{name}: port must be an integer, got {port}"
        assert port.get("minimum") == 1, (
            f"{name}: port minimum must be 1, got {port.get('minimum')}"
        )
        assert port.get("maximum") == 65535, (
            f"{name}: port maximum must be 65535, got {port.get('maximum')}"
        )
