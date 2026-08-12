"""Shared upper bounds for tool parameters that would otherwise be unbounded.

A tool timeout is not only a local wait. The MCP transport hands each call to a
bounded thread pool, so an unbounded value holds a pool slot for exactly as long
as the caller asked for, and a caller that asks for a day gets a day. These
aliases put every wait inside a range the server can survive, and the generated
schema rejects anything larger before a backend is touched.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

# Run control (launch/attach/pause/resume/step/wait). The ceiling matches the
# service-side _MAX_WORKFLOW_TIMEOUT so the schema and the domain agree.
RunControlTimeout = Annotated[float, Field(gt=0, le=300.0)]

# External unpackers and CLI tools legitimately outlast a debugger operation.
ExternalToolTimeout = Annotated[float, Field(gt=0, le=600.0)]
