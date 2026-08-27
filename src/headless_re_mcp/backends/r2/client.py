from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.bounded_run import TimedOut, run_bounded
from headless_re_mcp.backends.r2.mapping import enrich_r2_payload, parse_r2_json_values

JsonObject = dict[str, Any]
_MAX_OUTPUT = 1_000_000
_ALLOWED = frozenset(
    {
        "i",
        "ii",
        "iI",
        "is",
        "il",
        "ie",
        "aflj",
        "izj",
        "iij",
        "iEj",
        "pdj",
        "axj",
        "aa",
    }
)
_PDJ_COMMAND = re.compile(r"pdj ([1-9][0-9]*) @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")
_AXJ_COMMAND = re.compile(r"axj @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")
# axtj (refs to) and axfj (refs from) honour the @ address; plain axj ignores
# it and lists the whole program, which is why xrefs() uses these two instead.
_AXTF_COMMAND = re.compile(r"ax[tf]j @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")


class R2Error(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _require_allowed_command(command: str) -> None:
    if command in _ALLOWED:
        return
    pdj = _PDJ_COMMAND.fullmatch(command)
    if pdj is not None and int(pdj.group(1)) <= 512:
        return
    if _AXJ_COMMAND.fullmatch(command) is not None:
        return
    if _AXTF_COMMAND.fullmatch(command) is not None:
        return
    raise R2Error("invalid_params", "r2 command not whitelisted", command=command)


class R2Client:
    def __init__(self, executable: Path | None = None) -> None:
        self.executable = executable or _discover()

    @property
    def available(self) -> bool:
        return self.executable is not None and self.executable.is_file()

    def open(self, binary: Path, *, timeout: float = 30.0) -> JsonObject:
        """Validate that r2 can open ``binary`` (one-shot; no persistent pipe)."""
        if not binary.is_file():
            raise R2Error("not_found", "binary not found", path=str(binary))
        data = self.run(binary, ["i"], timeout=timeout)
        return {
            "opened": True,
            "binary": str(binary),
            "info": data.get("raw", "")[:8000],
            "note": "r2.open is one-shot validation; subsequent tools reopen the binary",
        }

    def disasm(
        self,
        binary: Path,
        address: int,
        *,
        count: int = 32,
        timeout: float = 30.0,
    ) -> JsonObject:
        if type(address) is not int or address < 0:
            raise R2Error("invalid_params", "address must be a non-negative int")
        if type(count) is not int or not 1 <= count <= 512:
            raise R2Error("invalid_params", "count must be 1..512")
        cmd = f"pdj {count} @ {address}"
        data = self.run(binary, ["aa", cmd], timeout=timeout)
        data = dict(data)
        data["address"] = address
        data["count"] = count
        result = enrich_r2_payload(data, binary=binary)
        # r2 does not fail on an unmapped or non-code address: it reads the hole
        # as 0xff and returns `count` instructions all typed "invalid", which
        # otherwise pass through looking like a real disassembly. Count them so
        # invalid_count == count says "nothing decodable here" (unmapped,
        # misspelled, or not code) rather than letting the filler read as code.
        items = result.get("items")
        if isinstance(items, list):
            result["invalid_count"] = sum(
                1 for item in items if isinstance(item, dict) and item.get("type") == "invalid"
            )
        return result

    def xrefs(
        self,
        binary: Path,
        address: int,
        *,
        timeout: float = 30.0,
    ) -> JsonObject:
        if type(address) is not int or address < 0:
            raise R2Error("invalid_params", "address must be a non-negative int")
        # `axj @ addr` ignores the address and lists every reference in the
        # binary; `axtj` (to) and `axfj` (from) are the ones that honour it. Run
        # both in one analysis pass and merge into a directed edge list so the
        # result actually describes the address that was asked for.
        data = self.run(
            binary,
            ["aa", f"axtj @ {address}", f"axfj @ {address}"],
            timeout=timeout,
        )
        values = parse_r2_json_values(str(data.get("raw") or ""))
        arrays = [value for value in values if isinstance(value, list)]
        to_refs = arrays[0] if len(arrays) >= 1 else []
        from_refs = arrays[1] if len(arrays) >= 2 else []
        edges = _merge_xref_edges(to_refs, from_refs, address)
        enriched = enrich_r2_payload(
            {"raw": data.get("raw", ""), "commands": data.get("commands"), "address": address},
            binary=binary,
            parsed_override=edges,
        )
        enriched["xrefs_to"] = len(to_refs)
        enriched["xrefs_from"] = len(from_refs)
        # Carry any raw-output truncation the underlying run recorded; a cut that
        # lost the second array must not read as "no refs from here".
        for key in ("truncated", "output_bytes", "returned_bytes"):
            if key in data:
                enriched[key] = data[key]
        return enriched

    def run(self, binary: Path, commands: list[str], *, timeout: float = 30.0) -> JsonObject:
        if not self.available or self.executable is None:
            raise R2Error("capability_unavailable", "radare2/rizin is not installed")
        if not binary.is_file():
            raise R2Error("not_found", "binary not found", path=str(binary))
        for cmd in commands:
            _require_allowed_command(cmd)
        script = "\n".join([*commands, "q"])
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        try:
            # r2 on PATH is often a launcher script, and subprocess.run kills
            # only that process then drains with no deadline. Measured: a stub
            # that started a child and held the pipes did not return 8s after a
            # 0.8s timeout, and the child was still running.
            completed = run_bounded(
                [str(self.executable), "-q0", "-c", script, str(binary)],
                timeout=timeout,
                creationflags=creationflags,
            )
        except TimedOut as exc:
            raise R2Error(
                "timeout",
                "r2 timed out",
                timeout=timeout,
                killed_pids=exc.killed,
            ) from exc
        except OSError as exc:
            # A configured executable that is present but cannot be launched --
            # not marked +x, or replaced between the is_file() check and the
            # spawn -- makes Popen raise OSError (PermissionError for a
            # non-executable file). Uncaught, that reaches the service envelope
            # as an internal_error with a logged incident, casting a backend
            # misconfiguration as a server defect. The sibling adapters (jadx,
            # apktool, jsre, windbg) all map this to backend_error; r2 did not.
            raise R2Error(
                "backend_error",
                f"failed to launch {self.executable}: {exc}",
            ) from exc
        produced = len(completed.stdout)
        out = completed.stdout[:_MAX_OUTPUT]
        err = completed.stderr[:_MAX_OUTPUT]
        if completed.returncode != 0:
            raise R2Error(
                "backend_error",
                "r2 exited non-zero",
                exit_code=completed.returncode,
                stderr=err.decode("utf-8", errors="replace")[:2000],
            )
        payload: JsonObject = {
            "raw": out.decode("utf-8", errors="replace"),
            "commands": commands,
        }
        if produced > _MAX_OUTPUT:
            # Cut silently, a listing that stopped at the buffer looks like a
            # listing that ended, and this is the analysis text a caller reads
            # to decide where a function finishes.
            payload["truncated"] = True
            payload["output_bytes"] = produced
            payload["returned_bytes"] = len(out)
        return enrich_r2_payload(payload, binary=binary)


def _merge_xref_edges(
    to_refs: list[Any], from_refs: list[Any], address: int
) -> list[JsonObject]:
    """Combine axtj (to) and axfj (from) into one direction-tagged edge list.

    axtj items carry the referrer as ``from`` and leave the queried address
    implicit, so the queried address is filled in as ``to``. axfj items already
    carry both endpoints. ``direction`` says which query produced each edge so a
    caller reading the merged list can still tell "who references this" from
    "what this references".
    """
    edges: list[JsonObject] = []
    for ref in to_refs:
        if not isinstance(ref, dict):
            continue
        edge = dict(ref)
        edge["direction"] = "to"
        edge.setdefault("to", address)
        edges.append(edge)
    for ref in from_refs:
        if not isinstance(ref, dict):
            continue
        edge = dict(ref)
        edge["direction"] = "from"
        edge.setdefault("from", address)
        edges.append(edge)
    return edges


def _discover() -> Path | None:
    for name in ("r2", "rizin", "radare2"):
        found = shutil.which(name)
        if found:
            return Path(found)
    return None
