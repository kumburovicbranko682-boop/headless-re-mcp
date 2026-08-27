"""OEP candidate heuristics — multi-signal scoring, never authoritative alone."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

JsonObject = dict[str, Any]


@dataclass(frozen=True, slots=True)
class OepSignal:
    kind: str
    weight: float
    description: str
    details: JsonObject = field(default_factory=dict)

    def to_dict(self) -> JsonObject:
        return {
            "kind": self.kind,
            "weight": self.weight,
            "description": self.description,
            "details": dict(self.details),
        }


class ScoredOep(list[JsonObject]):
    """The scored candidate dicts, plus how many were scored before the cap.

    ``score_oep_candidates`` returns the highest-scoring ``limit`` candidates.
    Every existing caller treats the result as a plain list -- ``len``,
    indexing, iteration, ``tuple(...)``, ``== []`` -- and all of that still
    holds because this *is* a list. What a bare list cannot say is that
    lower-scored candidates were dropped to honour the cap: a caller reading the
    length as "candidates found" would read the top 8 of 30 as "8 found", the
    same silent cut every other listing in this project is careful to disclose.
    ``total`` (distinct RVAs that scored at all), ``limit`` (the cap) and
    ``truncated`` ride along so the service layer can report the cut with the
    familiar ``*_truncated`` / ``*_total`` / ``*_limit`` trio.
    """

    def __init__(self, candidates: list[JsonObject], *, total: int, limit: int) -> None:
        super().__init__(candidates)
        self.total = total
        self.limit = limit
        self.truncated = total > limit


@dataclass(frozen=True, slots=True)
class OepCandidate:
    candidate_id: str
    oep_rva: int
    oep_va: int | None
    score: float
    signals: tuple[OepSignal, ...]
    role: str = "first_native_handoff"
    note: str = "heuristic only; caller must confirm"

    def to_dict(self) -> JsonObject:
        return {
            "candidate_id": self.candidate_id,
            "oep_rva": self.oep_rva,
            "oep_va": self.oep_va,
            "score": round(self.score, 4),
            "role": self.role,
            "signals": [signal.to_dict() for signal in self.signals],
            "authoritative": False,
            "note": self.note,
        }


def score_oep_candidates(
    *,
    module_base: int,
    module_size: int,
    observations: list[JsonObject] | tuple[JsonObject, ...],
    stub_rva_ranges: list[tuple[int, int]] | tuple[tuple[int, int], ...] = (),
    max_candidates: int = 8,
) -> ScoredOep:
    """Score OEP candidates from runtime observations.

    Supported observation kinds (M5.2):
    - ``ep_section_protect_changed``
    - ``new_executable_region``
    - ``write_to_execute``
    - ``rip_in_main_module_code``
    - ``imports_resolved``
    - ``left_stub_region``
    - ``packed_ep`` (packed AddressOfEntryPoint / stub EP; role hint)
    - ``first_native_handoff`` (first native CODE handoff; not classic OEP)

    Returns a :class:`ScoredOep` -- a list of the highest-scoring candidate
    dicts capped at ``max_candidates`` -- that also reports ``total`` (how many
    distinct RVAs scored before the cap), ``limit`` and ``truncated``, so a cut
    that dropped lower-scored candidates is disclosed rather than silent.
    """
    if type(module_base) is not int or module_base <= 0:
        raise ValueError("module_base must be a positive integer")
    if type(module_size) is not int or module_size <= 0:
        raise ValueError("module_size must be a positive integer")
    if max_candidates <= 0:
        raise ValueError("max_candidates must be positive")

    buckets: dict[int, list[OepSignal]] = {}
    roles: dict[int, str] = {}

    for index, item in enumerate(observations):
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind", ""))
        rva = _as_rva(item, module_base)
        if rva is None:
            continue
        if not 0 <= rva < module_size:
            continue
        explicit_role = item.get("role")
        if isinstance(explicit_role, str) and explicit_role in {
            "packed_ep",
            "first_native_handoff",
            "confirmed",
        }:
            roles[rva] = explicit_role
        elif kind == "packed_ep":
            roles.setdefault(rva, "packed_ep")
        elif kind == "first_native_handoff":
            roles.setdefault(rva, "first_native_handoff")
        signal = _signal_for(kind, item, index)
        if signal is None:
            continue
        # Leaving stub: prefer RVAs outside stub ranges.
        if kind == "left_stub_region" and _in_ranges(rva, stub_rva_ranges):
            signal = OepSignal(
                kind=signal.kind,
                weight=max(0.05, signal.weight * 0.25),
                description=signal.description + " (still inside stub range)",
                details=signal.details,
            )
        # RIP still inside VMP/stub sections is not a native CODE handoff.
        if kind == "rip_in_main_module_code" and _in_ranges(rva, stub_rva_ranges):
            signal = OepSignal(
                kind=signal.kind,
                weight=max(0.05, signal.weight * 0.2),
                description=signal.description + " (inside protector stub section)",
                details={**signal.details, "in_stub_section": True},
            )
            roles.setdefault(rva, "packed_ep")
        buckets.setdefault(rva, []).append(signal)

    candidates: list[OepCandidate] = []
    for rva, signals in buckets.items():
        # Cap per-kind contribution so one noisy signal cannot dominate.
        by_kind: dict[str, float] = {}
        for signal in signals:
            by_kind[signal.kind] = max(by_kind.get(signal.kind, 0.0), signal.weight)
        score = min(1.0, sum(by_kind.values()))
        # Single-signal candidates stay low-confidence.
        if len(by_kind) == 1:
            score = min(score, 0.45)
        role = roles.get(rva, "first_native_handoff")
        if role == "confirmed":
            # Heuristic scoring never emits confirmed; clamp misuse.
            role = "first_native_handoff"
        candidates.append(
            OepCandidate(
                candidate_id=f"oep-{rva:x}",
                oep_rva=rva,
                oep_va=module_base + rva,
                score=score,
                signals=tuple(signals),
                role=role,
            )
        )

    candidates.sort(key=lambda item: (-item.score, item.oep_rva))
    total = len(candidates)
    if total > max_candidates:
        # Kept for disclosure, not dropped in silence: the lowest-scored buckets
        # are cut so one run cannot flood the caller, but ScoredOep carries the
        # pre-cut total so "candidate_count" is never mistaken for "all found".
        candidates = candidates[:max_candidates]
    return ScoredOep(
        [item.to_dict() for item in candidates],
        total=total,
        limit=max_candidates,
    )


def _as_rva(item: JsonObject, module_base: int) -> int | None:
    if "oep_rva" in item and item["oep_rva"] is not None:
        value = item["oep_rva"]
        if type(value) is not int or value < 0:
            return None
        return value
    if "address" in item and item["address"] is not None:
        value = item["address"]
        if type(value) is not int:
            return None
        if value >= module_base:
            return value - module_base
        return value
    if "rip" in item and item["rip"] is not None:
        value = item["rip"]
        if type(value) is not int:
            return None
        if value >= module_base:
            return value - module_base
        return None
    return None


def _in_ranges(rva: int, ranges: list[tuple[int, int]] | tuple[tuple[int, int], ...]) -> bool:
    return any(start <= rva < start + size for start, size in ranges)


def _signal_for(kind: str, item: JsonObject, index: int) -> OepSignal | None:
    weights = {
        "ep_section_protect_changed": 0.25,
        "new_executable_region": 0.2,
        "write_to_execute": 0.3,
        "rip_in_main_module_code": 0.35,
        "imports_resolved": 0.25,
        "left_stub_region": 0.2,
        "packed_ep": 0.15,
        "first_native_handoff": 0.3,
    }
    if kind not in weights:
        return None
    description = str(item.get("description") or _default_description(kind))
    details = {
        key: value
        for key, value in item.items()
        if key not in {"kind", "description", "oep_rva", "address", "rip", "role"}
    }
    details["observation_index"] = index
    return OepSignal(
        kind=kind,
        weight=float(item.get("weight", weights[kind])),
        description=description,
        details=details,
    )


def _default_description(kind: str) -> str:
    return {
        "ep_section_protect_changed": "Entry-point section protection changed",
        "new_executable_region": "New executable memory region observed",
        "write_to_execute": "Page transitioned from writable to executable",
        "rip_in_main_module_code": "Control flow returned to main-module code",
        "imports_resolved": "Import resolution appears complete",
        "left_stub_region": "Execution left the packer stub region",
        "packed_ep": "Packed AddressOfEntryPoint / stub entry (not original OEP)",
        "first_native_handoff": "First native CODE handoff after unpack stub",
    }.get(kind, kind)
