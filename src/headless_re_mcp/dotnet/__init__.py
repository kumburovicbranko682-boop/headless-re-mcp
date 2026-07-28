""".NET adapters (M6)."""

from headless_re_mcp.dotnet.clr_inspect import (
    DotnetInspectError,
    DotnetInspectReport,
    DotnetKind,
    inspect_dotnet,
)
from headless_re_mcp.dotnet.de4dot import (
    DE4DOT_SOURCE,
    De4dotError,
    De4dotResult,
    run_de4dot,
)
from headless_re_mcp.dotnet.metadata_enum import (
    CAPABILITY as DOTNET_METADATA_CAPABILITY,
)
from headless_re_mcp.dotnet.metadata_enum import (
    disassemble_method_il,
    enumerate_metadata,
    list_memberref_xrefs,
)
from headless_re_mcp.dotnet.net_reactor_slayer import (
    NRS_SOURCE,
    NetReactorSlayerError,
    NetReactorSlayerResult,
    run_net_reactor_slayer,
)

__all__ = [
    "DE4DOT_SOURCE",
    "DOTNET_METADATA_CAPABILITY",
    "De4dotError",
    "De4dotResult",
    "DotnetInspectError",
    "DotnetInspectReport",
    "DotnetKind",
    "NRS_SOURCE",
    "NetReactorSlayerError",
    "NetReactorSlayerResult",
    "disassemble_method_il",
    "enumerate_metadata",
    "inspect_dotnet",
    "list_memberref_xrefs",
    "run_de4dot",
    "run_net_reactor_slayer",
]
