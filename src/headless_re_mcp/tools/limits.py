"""Shared parameter types for tools: numeric bounds and closed-value enums.

A tool timeout is not only a local wait. The MCP transport hands each call to a
bounded thread pool, so an unbounded value holds a pool slot for exactly as long
as the caller asked for, and a caller that asks for a day gets a day. These
aliases put every wait inside a range the server can survive, and the generated
schema rejects anything larger before a backend is touched. The same reasoning
applies to closed string vocabularies: advertising the allowed set as an enum
lets the schema (and the LLM reading it) refuse a typo instead of round-tripping
an invalid value to the domain layer.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

# Run control (launch/attach/pause/resume/step/wait). The ceiling matches the
# service-side _MAX_WORKFLOW_TIMEOUT so the schema and the domain agree.
RunControlTimeout = Annotated[float, Field(gt=0, le=300.0)]

# External unpackers and CLI tools legitimately outlast a debugger operation.
ExternalToolTimeout = Annotated[float, Field(gt=0, le=600.0)]

# IAT candidate scan strategy. imports.scan / unpack.iat.scan share this closed
# set with the service (AnalysisService.imports_scan rejects anything else with
# invalid_params) and the native ScanImports guard ("mode must be
# consecutive|sparse|call_site|all"). Typed as a bare str the schema advertised
# only "string", so an agent had to guess -- a natural "linear"/"full" failed at
# the service boundary instead of being refused as an out-of-enum value up front.
ImportScanMode = Literal["all", "consecutive", "sparse", "call_site"]
