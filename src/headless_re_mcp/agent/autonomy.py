"""Policy that decides which Agent tool calls may run without a human.

The Agent is fail-closed by default: only read-only tools execute on their own
and everything that changes state or writes a file waits for an explicit
approval, which is the right default for a debugger that runs untrusted code.
That default also makes unattended operation impossible, because nobody is there
to approve and the run fails on the approval timeout.

This is the opt-in that reopens it, expressed as an allowlist rather than a
switch: with no configuration the policy grants exactly what the fail-closed
model already granted, so the safe default is structural instead of something an
operator has to remember to re-deny.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from headless_re_mcp.tools.catalog import CommandSpec, ToolEffect


@dataclass(frozen=True, slots=True)
class AutoApproval:
    """Whether a call may proceed unattended, and the rule that decided it."""

    approved: bool
    reason: str

    def as_json(self) -> dict[str, object]:
        return {"approved": self.approved, "reason": self.reason}


def _effects(values: Iterable[str]) -> frozenset[ToolEffect]:
    resolved: set[ToolEffect] = set()
    for raw in values:
        name = str(raw).strip().casefold()
        if not name:
            continue
        try:
            resolved.add(ToolEffect(name))
        except ValueError as exc:
            allowed = ", ".join(sorted(item.value for item in ToolEffect))
            raise ValueError(f"unknown tool effect {name!r}; expected one of: {allowed}") from exc
    return frozenset(resolved)


def _names(values: Iterable[str]) -> frozenset[str]:
    return frozenset(str(item).strip() for item in values if str(item).strip())


@dataclass(frozen=True, slots=True)
class AutonomyPolicy:
    """Allowlist of what the Agent may execute without waiting for a human."""

    auto_approve_effects: frozenset[ToolEffect] = frozenset()
    auto_approve_tools: frozenset[str] = frozenset()
    never_auto_approve: frozenset[str] = frozenset()

    @classmethod
    def from_settings(cls, settings: object) -> AutonomyPolicy:
        return cls(
            auto_approve_effects=_effects(
                getattr(settings, "agent_auto_approve_effects", ()) or ()
            ),
            auto_approve_tools=_names(getattr(settings, "agent_auto_approve_tools", ()) or ()),
            never_auto_approve=_names(getattr(settings, "agent_never_auto_approve", ()) or ()),
        )

    @property
    def unattended(self) -> bool:
        """True once anything beyond the read-only baseline may run on its own."""
        return bool(self.auto_approve_effects or self.auto_approve_tools)

    def decide(self, spec: CommandSpec) -> AutoApproval:
        """Resolve one tool against the policy.

        A denial wins over every grant, including the read-only baseline, so an
        operator who names a tool here can be certain it always stops for a
        human. Grants are ordered most specific first purely so the recorded
        reason names the rule that actually applied.
        """
        if spec.name in self.never_auto_approve:
            return AutoApproval(False, "never_auto_approve")
        if spec.effects == frozenset({ToolEffect.READ_ONLY}):
            return AutoApproval(True, "read_only")
        if spec.name in self.auto_approve_tools:
            return AutoApproval(True, "allowlisted_tool")
        if spec.effects and spec.effects <= self.auto_approve_effects:
            granted = ",".join(sorted(effect.value for effect in spec.effects))
            return AutoApproval(True, f"allowlisted_effects:{granted}")
        return AutoApproval(False, "requires_human")

    def describe(self) -> dict[str, object]:
        return {
            "unattended": self.unattended,
            "auto_approve_effects": sorted(item.value for item in self.auto_approve_effects),
            "auto_approve_tools": sorted(self.auto_approve_tools),
            "never_auto_approve": sorted(self.never_auto_approve),
        }