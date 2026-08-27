from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.bounded_run import TimedOut, run_bounded
from headless_re_mcp.backends.r2.mapping import _item_va, enrich_r2_payload, parse_r2_arrays

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
        "iSj",
        "pdj",
        "axj",
        "aa",
    }
)
_PDJ_COMMAND = re.compile(r"pdj ([1-9][0-9]*) @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")
# axj (whole DB), axtj (refs to), axfj (refs from), each seeked with ``@ addr``.
# r2 6.x makes ``axj @ addr`` return nothing, so xrefs queries axtj/axfj, which
# honour the seek on every version; axj stays whitelisted for the enrich filter
# path and older builds.
_AXREF_COMMAND = re.compile(r"ax[tf]?j @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")


def _is_invalid_op(item: JsonObject) -> bool:
    """Whether an r2 disasm row is an undecodable byte rather than an opcode.

    radare2 tags these ``type: "invalid"`` on 5.x but ``type: "ill"`` (with
    ``opcode: "invalid"``) on 6.x. Matching only the old spelling made
    ``invalid_count`` read 0 for a header or a data hole on a current r2, the
    exact "this address is not code" signal the field exists to give.
    """
    if str(item.get("type", "")).strip().lower() in {"invalid", "ill"}:
        return True
    return str(item.get("opcode", "")).strip().lower() == "invalid"


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
    if _AXREF_COMMAND.fullmatch(command) is not None:
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
        enriched = enrich_r2_payload(data, binary=binary)
        # Point pdj at data, padding, or unmapped memory and r2 still returns a
        # row per byte -- each tagged type "invalid" with no opcode. Structurally
        # that is indistinguishable from a decoded run, so an agent that only
        # reads count/items would treat header bytes as instructions. Count the
        # undecodable rows out loud so "this address is not code" is legible
        # without walking every item.
        items = enriched.get("items")
        if isinstance(items, list):
            enriched["invalid_count"] = sum(
                1 for item in items if isinstance(item, dict) and _is_invalid_op(item)
            )
        return enriched

    def xrefs(
        self,
        binary: Path,
        address: int,
        *,
        timeout: float = 30.0,
    ) -> JsonObject:
        if type(address) is not int or address < 0:
            raise R2Error("invalid_params", "address must be a non-negative int")
        # "References to and from address." The old single ``axj @ addr`` listed
        # the whole database and ignored the seek on every version, and on r2 6.x
        # it returns nothing at all -- so xrefs silently went empty on a current
        # r2. ``axtj``/``axfj`` are seeked by r2 itself on both 5.x and 6.x: axtj
        # yields the rows that reference `address` (it is their target), axfj the
        # rows `address` references (it is their origin). Query both in one
        # analysis pass and normalise each into a {from, to} pair so the endpoint
        # the caller did not name is filled with the address they asked about.
        to_cmd = f"axtj @ {address}"
        from_cmd = f"axfj @ {address}"
        data = self.run(binary, ["aa", to_cmd, from_cmd], timeout=timeout)
        arrays = parse_r2_arrays(str(data.get("raw") or ""))
        to_rows = arrays[0] if len(arrays) >= 1 else []
        from_rows = arrays[1] if len(arrays) >= 2 else []
        merged: list[JsonObject] = []
        for row in to_rows:
            if not isinstance(row, dict):
                continue
            origin = _item_va(row, ("from", "fromaddr", "addr"))
            merged.append({**row, "from": origin, "to": address, "direction": "to"})
        for row in from_rows:
            if not isinstance(row, dict):
                continue
            target = _item_va(row, ("to", "toaddr", "addr"))
            merged.append({**row, "from": address, "to": target, "direction": "from"})
        payload: JsonObject = {
            "raw": json.dumps(merged),
            "commands": ["aa", to_cmd, from_cmd],
            "address": address,
        }
        return enrich_r2_payload(payload, binary=binary)

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


def _discover() -> Path | None:
    for name in ("r2", "rizin", "radare2"):
        found = shutil.which(name)
        if found:
            return Path(found)
    return None
