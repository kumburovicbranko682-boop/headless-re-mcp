# ADR: Explicit application and transport boundaries

- Status: Accepted
- Date: 2026-07-28

## Context

The public `AnalysisService` accumulated backend lifecycle, dynamic debugging, UI interaction, workflow, unpack/trace, and persistence responsibilities. MCP and Web also encoded overlapping command policy independently. Runtime method injection made the actual service surface invisible to static analysis.

## Decision

1. Keep `AnalysisService` as a compatibility façade so public tools, arguments, result envelopes, CLI/Web behavior, and private test compatibility views remain stable.
2. Compose static mixins and explicit `ApplicationServices`; runtime method injection is prohibited.
3. Assign runtime, debuggee, workflow, unpack, and trace data to dedicated state owners. Compatibility fields are aliases to owner-managed state only.
4. Replace cross-domain `_sync_dynamic_state` with `DebuggeeStateOwner.observe`, the single debuggee-to-session projection boundary.
5. Route session, backend, audit, timeline, artifact, and unpack snapshot effects through `AnalysisRepository`; use `SqliteAnalysisRepository` as the default serialized persistence boundary.
6. Share `CommandSpec` metadata between MCP and Web. MCP binding stores the typed handler, generated input schema, description, transport policy, and service mapping in that catalog.
7. Keep the debugger API allowlisted. No generic x64dbg command execution endpoint will be introduced.

## Consequences

- State ownership and lock scope are explicit and independently testable.
- Persistence can be replaced without changing the façade's public contract.
- Web write policy and MCP command metadata are derived from one catalog.
- Existing callers continue to work while selected façade entry points delegate to domain application services.
- Compatibility aliases are transitional; new code must depend on owners and ports rather than private dictionaries.