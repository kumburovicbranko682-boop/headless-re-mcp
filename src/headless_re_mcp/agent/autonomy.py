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
from enum import StrEnum

from headless_re_mcp.tools.catalog import COMMAND_CATALOG, CommandSpec, CommandTransport, ToolEffect

WRITE_EFFECTS = frozenset({ToolEffect.STATE_CHANGE, ToolEffect.FILE_WRITE})


class ApprovalMode(StrEnum):
    """The two operator-facing switches. Granular allowlists still exist underneath."""

    REQUEST = "request"
    FULL_ACCESS = "full_access"


def parse_approval_mode(value: object) -> ApprovalMode:
    raw = str(value).strip().casefold().replace("-", "_")
    aliases = {"full": ApprovalMode.FULL_ACCESS, "ask": ApprovalMode.REQUEST}
    if raw in aliases:
        return aliases[raw]
    try:
        return ApprovalMode(raw)
    except ValueError as exc:
        allowed = ", ".join(item.value for item in ApprovalMode)
        raise ValueError(f"unknown approval mode {value!r}; expected one of: {allowed}") from exc


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


# Packed PE analysis is the unattended default. Empty policy objects in tests
# stay fail-closed; Settings.load() applies this preset when the operator has
# not set the keys. Patches, APK/Web rewrite, and artifact GC stay denied.
_EXCLUDED_AUTO_FILE_WRITES = frozenset(
    {
        "artifacts.gc",
        "patches.apply",
        "patches.restore",
        "static.bytes.patch",
        "report.generate",
        "apk.decode",
        "apk.decompile",
        "apk.export_sources",
        "apk.repack",
        "apk.sign",
        "device.pull",
        "device.screenshot",
        "js.unpack_bundle",
        "proxy.export_har",
        "web.har.export",
        "web.screenshot",
    }
)
# Granting the state_change class by effect (rather than by an allowlist of
# named tools, the way file writes are handled above) is deliberate: packed-PE
# analysis needs the whole dynamic/unpack/workflow surface to run unattended and
# enumerating it would be churny and fragile. The consequence is that the same
# grant also sweeps in every non-PE state change -- device.* mutations, the
# frida.* device path, proxy.start/stop, the web.* browser drive and
# workspace.mode.set -- none of which are packed-PE work but all of which then
# auto-run under the default preset. Unlike the file-write denylist, an effect
# grant has no place to record which tools it covers, so a newly added non-PE
# state-change tool would silently join this unattended set with no review. The
# set is therefore pinned against the shipped catalog in test_agent_autonomy.py
# (test_non_pe_state_change_tools_riding_the_packed_preset_are_pinned) so adding
# one trips a test and forces a conscious acknowledgement that it auto-runs.
PACKED_ANALYSIS_AUTO_APPROVE_EFFECTS: tuple[str, ...] = ("state_change",)
PACKED_ANALYSIS_AUTO_APPROVE_TOOLS: tuple[str, ...] = tuple(
    sorted(
        spec.name
        for spec in COMMAND_CATALOG.for_transport(CommandTransport.AGENT)
        if ToolEffect.FILE_WRITE in spec.effects
        and spec.name not in _EXCLUDED_AUTO_FILE_WRITES
    )
)


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

    @property
    def mode(self) -> ApprovalMode:
        """Collapse the allowlist into the two Web UI switches.

        Full access means every write effect class is open. Anything narrower,
        including a handful of remembered tools, still shows as request so the
        operator is not told the workbench is unrestricted when it is not.
        """
        if self.auto_approve_effects >= WRITE_EFFECTS:
            return ApprovalMode.FULL_ACCESS
        return ApprovalMode.REQUEST

    def with_mode(self, mode: str | ApprovalMode) -> AutonomyPolicy:
        """Replace grants with one of the two operator-facing modes.

        ``never_auto_approve`` is a hard stop and is left alone. Request clears
        every grant so writes wait again; full access opens both write effect
        classes so the next state-change or file-write call does not park.
        """
        resolved = mode if isinstance(mode, ApprovalMode) else parse_approval_mode(mode)
        if resolved is ApprovalMode.REQUEST:
            return AutonomyPolicy(
                auto_approve_effects=frozenset(),
                auto_approve_tools=frozenset(),
                never_auto_approve=self.never_auto_approve,
            )
        return AutonomyPolicy(
            auto_approve_effects=WRITE_EFFECTS,
            auto_approve_tools=frozenset(),
            never_auto_approve=self.never_auto_approve,
        )

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

    def grant(self, *, tools: Iterable[str] = (), effects: Iterable[str | ToolEffect] = ()) -> AutonomyPolicy:
        """Return a policy that also auto-approves these tools or effect classes."""
        extra: list[str] = []
        for item in effects:
            extra.append(item.value if isinstance(item, ToolEffect) else str(item))
        return AutonomyPolicy(
            auto_approve_effects=self.auto_approve_effects | _effects(extra),
            auto_approve_tools=self.auto_approve_tools | _names(tools),
            never_auto_approve=self.never_auto_approve,
        )

    def revoke_tools(self, tools: Iterable[str]) -> AutonomyPolicy:
        drop = _names(tools)
        return AutonomyPolicy(
            auto_approve_effects=self.auto_approve_effects,
            auto_approve_tools=self.auto_approve_tools - drop,
            never_auto_approve=self.never_auto_approve,
        )

    def describe(self) -> dict[str, object]:
        return {
            "mode": self.mode.value,
            "unattended": self.unattended,
            "auto_approve_effects": sorted(item.value for item in self.auto_approve_effects),
            "auto_approve_tools": sorted(self.auto_approve_tools),
            "never_auto_approve": sorted(self.never_auto_approve),
        }