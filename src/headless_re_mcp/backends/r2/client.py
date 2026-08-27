from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.bounded_run import TimedOut, run_bounded
from headless_re_mcp.backends.r2.mapping import enrich_r2_payload
from headless_re_mcp.core.models import Architecture

JsonObject = dict[str, Any]
# Architecture -> the (-a, -b) pair that makes r2 pick the matching slice of a
# fat Mach-O. Verified against r2 5.5.0 on a hand-crafted x86_64+arm64 fat:
# ``-a arm -b 64`` flips ``iI`` to arch arm and baddr to the arm64 slice's
# __TEXT vmaddr, while ``-a arm64`` and ``-e bin.arch=arm`` are both ignored
# and leave r2 on its host-dependent default pick.
_SLICE_FLAGS: dict[Architecture, tuple[str, str]] = {
    Architecture.X86: ("x86", "32"),
    Architecture.X64: ("x86", "64"),
    Architecture.ARM: ("arm", "32"),
    Architecture.ARM64: ("arm", "64"),
}
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
        # Deeper, still read-only analysis passes. ``aa`` alone is shallow: it
        # misses functions only reachable through a call (stripped binaries) and
        # data references formed by multi-instruction address materialisation
        # (ARM adrp/add). ``aac`` (analyze called functions), ``aar`` (analyze
        # data references) and the ``aaa`` umbrella recover those. They operate
        # on the already-opened image inside r2's own analyzer -- no target
        # execution, no host/file/network access -- so they do not widen the
        # command-injection surface the rest of this allowlist guards against.
        "aac",
        "aar",
        "aaa",
    }
)
_PDJ_COMMAND = re.compile(r"pdj ([1-9][0-9]*) @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")
_AXJ_COMMAND = re.compile(r"axj @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")
_AXTJ_COMMAND = re.compile(r"axtj @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")
_AXFFJ_COMMAND = re.compile(r"axffj @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")


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
    if _AXTJ_COMMAND.fullmatch(command) is not None:
        return
    if _AXFFJ_COMMAND.fullmatch(command) is not None:
        return
    raise R2Error("invalid_params", "r2 command not whitelisted", command=command)


class R2Client:
    def __init__(self, executable: Path | None = None) -> None:
        self.executable = executable or _discover()

    @property
    def available(self) -> bool:
        return self.executable is not None and self.executable.is_file()

    def open(
        self,
        binary: Path,
        *,
        timeout: float = 30.0,
        slice_arch: Architecture | None = None,
    ) -> JsonObject:
        """Validate that r2 can open ``binary`` (one-shot; no persistent pipe)."""
        if not binary.is_file():
            raise R2Error("not_found", "binary not found", path=str(binary))
        data = self.run(binary, ["i"], timeout=timeout, slice_arch=slice_arch)
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
        analysis: str = "aa",
        timeout: float = 30.0,
        slice_arch: Architecture | None = None,
    ) -> JsonObject:
        if type(address) is not int or address < 0:
            raise R2Error("invalid_params", "address must be a non-negative int")
        if type(count) is not int or not 1 <= count <= 512:
            raise R2Error("invalid_params", "count must be 1..512")
        cmd = f"pdj {count} @ {address}"
        data = self.run(binary, [analysis, cmd], timeout=timeout, slice_arch=slice_arch)
        data = dict(data)
        data["address"] = address
        data["count"] = count
        return enrich_r2_payload(data, binary=binary, slice_arch=slice_arch)

    def xrefs(
        self,
        binary: Path,
        address: int,
        *,
        analysis: str = "aa",
        timeout: float = 30.0,
        slice_arch: Architecture | None = None,
    ) -> JsonObject:
        if type(address) is not int or address < 0:
            raise R2Error("invalid_params", "address must be a non-negative int")
        cmd = f"axj @ {address}"
        data = self.run(binary, [analysis, cmd], timeout=timeout, slice_arch=slice_arch)
        data = dict(data)
        data["address"] = address
        return enrich_r2_payload(data, binary=binary, slice_arch=slice_arch)

    def xrefs_to(
        self,
        binary: Path,
        address: int,
        *,
        analysis: str = "aa",
        timeout: float = 30.0,
        slice_arch: Architecture | None = None,
    ) -> JsonObject:
        """References that target ``address`` (``axtj``), not the global graph.

        ``xrefs`` runs ``axj``, whose list is the same regardless of the seek --
        it answers "every cross-reference in the binary", so the address the
        caller passed is only echoed back, never used to filter. That is the
        wrong tool for "who calls this function". ``axtj`` seeks to ``address``
        and returns only the references pointing at it: each item carries the
        call/data site in ``from`` (mapped to ``from_address``) and the
        enclosing function in ``fcn_addr``/``fcn_name``, so a caller can walk
        the graph inbound one address at a time.

        ``analysis`` selects the analysis pass run before the query. The default
        ``aa`` is fast but shallow; pass a deeper pass (e.g. ``aaa``) to recover
        references ``aa`` misses -- notably ARM ``adrp/add`` data loads. It is
        validated against the same command allowlist as everything else.
        """
        if type(address) is not int or address < 0:
            raise R2Error("invalid_params", "address must be a non-negative int")
        cmd = f"axtj @ {address}"
        data = self.run(binary, [analysis, cmd], timeout=timeout, slice_arch=slice_arch)
        data = dict(data)
        data["address"] = address
        return enrich_r2_payload(data, binary=binary, slice_arch=slice_arch)

    def xrefs_from(
        self,
        binary: Path,
        address: int,
        *,
        analysis: str = "aa",
        timeout: float = 30.0,
        slice_arch: Architecture | None = None,
    ) -> JsonObject:
        """References made *from* the function containing ``address`` (``axffj``).

        The outbound complement of ``xrefs_to``: it answers "what does this
        function call and touch". ``axffj`` walks the whole function body, so a
        function entry returns its calls, string loads and internal jumps in one
        list -- unlike the per-instruction ``axfj``, which is empty at an entry
        because the first instruction references nothing. Each item names the
        target in ``name``/``type`` and carries the referencing site ``at``
        (mapped to ``at_address``) and the target ``ref`` (mapped to
        ``ref_address``, and to the item's ``address``).

        ``analysis`` selects the analysis pass, as on ``xrefs_to``. The default
        ``aa`` does not analyze functions reachable only through a call, so on a
        stripped binary ``axffj`` at such a function is empty; a deeper pass
        (e.g. ``aaa``) recovers the body and thus its outbound references.
        """
        if type(address) is not int or address < 0:
            raise R2Error("invalid_params", "address must be a non-negative int")
        cmd = f"axffj @ {address}"
        data = self.run(binary, [analysis, cmd], timeout=timeout, slice_arch=slice_arch)
        data = dict(data)
        data["address"] = address
        return enrich_r2_payload(data, binary=binary, slice_arch=slice_arch)

    def run(
        self,
        binary: Path,
        commands: list[str],
        *,
        timeout: float = 30.0,
        slice_arch: Architecture | None = None,
    ) -> JsonObject:
        if not self.available or self.executable is None:
            raise R2Error("capability_unavailable", "radare2/rizin is not installed")
        if not binary.is_file():
            raise R2Error("not_found", "binary not found", path=str(binary))
        for cmd in commands:
            _require_allowed_command(cmd)
        script = "\n".join([*commands, "q"])
        select: list[str] = []
        if slice_arch is not None:
            arch_name, bits = _SLICE_FLAGS[slice_arch]
            select = ["-a", arch_name, "-b", bits]
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        try:
            # r2 on PATH is often a launcher script, and subprocess.run kills
            # only that process then drains with no deadline. Measured: a stub
            # that started a child and held the pipes did not return 8s after a
            # 0.8s timeout, and the child was still running.
            completed = run_bounded(
                [str(self.executable), "-q0", *select, "-c", script, str(binary)],
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
        return enrich_r2_payload(payload, binary=binary, slice_arch=slice_arch)


def _discover() -> Path | None:
    for name in ("r2", "rizin", "radare2"):
        found = shutil.which(name)
        if found:
            return Path(found)
    return None
