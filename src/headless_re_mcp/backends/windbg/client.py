from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.bounded_run import TimedOut, run_bounded

JsonObject = dict[str, Any]
_ALLOWED_CMDS = frozenset({"lm", "k", "r", "u", "~*", "version", "vertarget"})


class WindbgError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


# cdb prints the whole session, and the analytical answer is in it. A listing
# that stopped at the cap is indistinguishable from a listing that ended, so
# the caller is told which of the two it is holding.
_MAX_OUTPUT = 500_000
_MAX_STDERR = 50_000
_MAX_ATTACH_OUTPUT = 8_000


def _bounded(raw: bytes, limit: int) -> tuple[str, dict[str, object]]:
    """Decode and cap ``raw``, plus the fields that say whether it was cut."""
    text = raw.decode("utf-8", errors="replace")
    if len(text) <= limit:
        return text, {}
    return text[:limit], {
        "truncated": True,
        "output_chars": len(text),
        "returned_chars": limit,
    }


def _summarised(text: str, limit: int) -> dict[str, object]:
    """The ``output`` field for a payload that carries nothing else to cut."""
    if len(text) <= limit:
        return {"output": text}
    return {
        "output": text[:limit],
        "truncated": True,
        "output_chars": len(text),
        "returned_chars": limit,
    }


def _carried(data: JsonObject) -> dict[str, object]:
    """Lift a truncation notice out of the raw payload a wrapper nests.

    Every wrapper here renames ``output`` to something the caller reads --
    threads, modules, disasm -- and files the rest under ``raw``. A caller
    reading the renamed field has no reason to open ``raw``, so the notice has
    to travel with it.
    """
    if not data.get("truncated"):
        return {}
    return {
        "truncated": True,
        "output_chars": data.get("output_chars"),
        "returned_chars": data.get("returned_chars"),
    }


def _is_store_package(path: Path) -> bool:
    """Microsoft Store package paths stat fine but CreateProcess denies them."""
    return "windowsapps" in str(path).casefold()


def _is_launchable_cdb(path: Path) -> bool:
    return path.is_file() and not _is_store_package(path)


class WindbgClient:
    def __init__(self, cdb: Path | None = None, *, allow_kernel: bool = False) -> None:
        self.cdb = cdb or _discover_cdb()
        self.allow_kernel = bool(allow_kernel)

    @property
    def available(self) -> bool:
        return self.cdb is not None and _is_launchable_cdb(self.cdb)

    def _require_cdb(self) -> Path:
        if self.cdb is not None and _is_store_package(self.cdb):
            raise WindbgError(
                "capability_unavailable",
                "cdb resolved to a Microsoft Store package path, which Windows "
                "refuses to launch directly; point HEADLESS_RE_CDB at a cdb.exe "
                "from the Windows SDK Debugging Tools instead",
                cdb=str(self.cdb),
            )
        if not self.available or self.cdb is None:
            raise WindbgError("capability_unavailable", "cdb/WinDbg is not installed")
        return self.cdb

    def open_dump(
        self,
        dump: Path,
        commands: list[str],
        *,
        timeout: float = 60.0,
        kernel: bool = False,
    ) -> JsonObject:
        if kernel and not self.allow_kernel:
            raise WindbgError(
                "permission_denied",
                "kernel dump analysis requires explicit HEADLESS_RE_WINDBG_ALLOW_KERNEL=1",
            )
        return self._run_dump(dump, commands, timeout=timeout)

    def threads(self, dump: Path, *, timeout: float = 60.0) -> JsonObject:
        data = self._run_dump(dump, ["~*"], timeout=timeout)
        return {"dump": str(dump), "threads": data.get("output", ""), "raw": data, **_carried(data)}

    def modules(self, dump: Path, *, timeout: float = 60.0) -> JsonObject:
        data = self._run_dump(dump, ["lm"], timeout=timeout)
        return {"dump": str(dump), "modules": data.get("output", ""), "raw": data, **_carried(data)}

    def disasm(
        self,
        dump: Path,
        address: str | int,
        *,
        length: int = 16,
        timeout: float = 60.0,
    ) -> JsonObject:
        if type(length) is not int or not 1 <= length <= 256:
            raise WindbgError("invalid_params", "length must be 1..256")
        if isinstance(address, int):
            if address < 0:
                raise WindbgError("invalid_params", "address must be non-negative")
            addr = hex(address)
        else:
            addr = str(address).strip()
            if not addr or any(ch in addr for ch in ";|&"):
                raise WindbgError("invalid_params", "invalid disasm address")
        # Whitelisted form: u <addr> L<count>
        cmd = f"u {addr} L{length}"
        data = self._run_dump(dump, [cmd], timeout=timeout)
        return {
            "dump": str(dump),
            "address": addr,
            "length": length,
            "disasm": data.get("output", ""),
            "raw": data,
            **_carried(data),
        }

    def attach(self, pid: int, *, allowed_pid: int, timeout: float = 30.0) -> JsonObject:
        """Non-invasive user-mode probe against a session debuggee PID."""
        data = self._run_process(
            pid,
            ["vertarget", "version"],
            allowed_pid=allowed_pid,
            timeout=timeout,
        )
        return {
            "pid": pid,
            "attached": True,
            "mode": "noninvasive",
            "note": "cdb -pv probe; detached via q",
            **_summarised(str(data.get("output", "")), _MAX_ATTACH_OUTPUT),
            "raw": data,
        }

    def live_threads(self, pid: int, *, allowed_pid: int, timeout: float = 30.0) -> JsonObject:
        data = self._run_process(pid, ["~*"], allowed_pid=allowed_pid, timeout=timeout)
        return {"pid": pid, "threads": data.get("output", ""), "raw": data, **_carried(data)}

    def live_modules(self, pid: int, *, allowed_pid: int, timeout: float = 30.0) -> JsonObject:
        data = self._run_process(pid, ["lm"], allowed_pid=allowed_pid, timeout=timeout)
        return {"pid": pid, "modules": data.get("output", ""), "raw": data, **_carried(data)}

    def live_disasm(
        self,
        pid: int,
        address: str | int,
        *,
        allowed_pid: int,
        length: int = 16,
        timeout: float = 30.0,
    ) -> JsonObject:
        if type(length) is not int or not 1 <= length <= 256:
            raise WindbgError("invalid_params", "length must be 1..256")
        if isinstance(address, int):
            if address < 0:
                raise WindbgError("invalid_params", "address must be non-negative")
            addr = hex(address)
        else:
            addr = str(address).strip()
            if not addr or any(ch in addr for ch in ";|&"):
                raise WindbgError("invalid_params", "invalid disasm address")
        cmd = f"u {addr} L{length}"
        data = self._run_process(pid, [cmd], allowed_pid=allowed_pid, timeout=timeout)
        return {
            "pid": pid,
            "address": addr,
            "length": length,
            "disasm": data.get("output", ""),
            "raw": data,
            **_carried(data),
        }

    def _run_process(
        self,
        pid: int,
        commands: list[str],
        *,
        allowed_pid: int,
        timeout: float,
    ) -> JsonObject:
        cdb = self._require_cdb()
        if type(pid) is not int or pid <= 0:
            raise WindbgError("invalid_params", "pid must be a positive integer")
        if pid != allowed_pid:
            raise WindbgError(
                "permission_denied",
                "windbg user-mode limited to session debuggee pid",
                pid=pid,
                allowed_pid=allowed_pid,
            )
        for cmd in commands:
            head = cmd.strip().split(" ", 1)[0]
            if head not in _ALLOWED_CMDS and cmd.strip() not in _ALLOWED_CMDS:
                raise WindbgError("invalid_params", "cdb command not whitelisted", command=cmd)
        script = "; ".join([*commands, "q"])
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        # -pv: non-invasive; can coexist with another debugger on the same PID.
        argv = [str(cdb), "-pv", "-p", str(pid), "-c", script]
        try:
            completed = run_bounded(argv, timeout=timeout, creationflags=creationflags)
        except TimedOut as exc:
            # cdb attaches to a live process; a deadline that only reaches the
            # launcher would leave a debugger holding the target.
            raise WindbgError(
                "timeout", "cdb timed out", timeout=timeout, killed_pids=exc.killed
            ) from exc
        except OSError as exc:
            raise WindbgError(
                "backend_error",
                f"cdb could not be launched: {exc.strerror or exc}",
                cdb=str(cdb),
            ) from exc
        out, cut = _bounded(completed.stdout, _MAX_OUTPUT)
        err, _ = _bounded(completed.stderr, _MAX_STDERR)
        if completed.returncode not in {0, 1} and not out:
            raise WindbgError(
                "backend_error",
                "cdb user-mode probe failed",
                exit_code=completed.returncode,
                stderr=err[:2000],
            )
        return {
            "pid": pid,
            "mode": "noninvasive",
            "output": out,
            "stderr": err,
            "exit_code": completed.returncode,
            **cut,
        }

    def _run_dump(self, dump: Path, commands: list[str], *, timeout: float) -> JsonObject:
        cdb = self._require_cdb()
        if not dump.is_file():
            raise WindbgError("not_found", "dump file not found", path=str(dump))
        for cmd in commands:
            head = cmd.strip().split(" ", 1)[0]
            if head not in _ALLOWED_CMDS and cmd.strip() not in _ALLOWED_CMDS:
                raise WindbgError("invalid_params", "cdb command not whitelisted", command=cmd)
        script = "; ".join([*commands, "q"])
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        try:
            completed = run_bounded(
                [str(cdb), "-z", str(dump), "-c", script],
                timeout=timeout,
                creationflags=creationflags,
            )
        except TimedOut as exc:
            raise WindbgError(
                "timeout", "cdb timed out", timeout=timeout, killed_pids=exc.killed
            ) from exc
        except OSError as exc:
            raise WindbgError(
                "backend_error",
                f"cdb could not be launched: {exc.strerror or exc}",
                cdb=str(cdb),
            ) from exc
        out, cut = _bounded(completed.stdout, _MAX_OUTPUT)
        err, _ = _bounded(completed.stderr, _MAX_STDERR)
        # Measured: exit 2 with stdout "Could not open dump\n" still became
        # threads="Could not open dump\n", so an unattended agent treats the
        # error text as the thread list.
        if completed.returncode not in {0, 1}:
            raise WindbgError(
                "backend_error",
                "cdb dump analysis failed",
                exit_code=completed.returncode,
                stderr=err[:2000],
            )
        return {
            "dump": str(dump),
            "output": out,
            "stderr": err,
            "exit_code": completed.returncode,
            **cut,
        }


def _discover_cdb() -> Path | None:
    env = os.environ.get("HEADLESS_RE_CDB")
    if env and Path(env).is_file():
        return Path(env)
    # Prefer the verified project runtime over a WindowsApps execution alias whose
    # package ACL can make ``is_file`` true while CreateProcess is denied.
    tools = Path(__file__).resolve().parents[4] / "artifacts" / "tools" / "cdb-amd64" / "cdb.exe"
    if tools.is_file():
        return tools
    found = shutil.which("cdb")
    if found and not _is_store_package(Path(found)):
        return Path(found)
    # Searching WindowsApps would only rediscover the unusable package path the
    # `which` filter above deliberately rejected.
    roots = [
        Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Windows Kits",
        Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")) / "Windows Kits",
    ]
    for root in roots:
        if not root.is_dir():
            continue
        matches = (
            list(root.glob("**/Debuggers/x64/cdb.exe"))
            + list(root.glob("**/amd64/cdb.exe"))
            + list(root.glob("**/x64/cdb.exe"))
            + list(root.glob("**/x86/cdb.exe"))
        )
        for match in matches:
            if _is_launchable_cdb(match):
                return match
    return None
