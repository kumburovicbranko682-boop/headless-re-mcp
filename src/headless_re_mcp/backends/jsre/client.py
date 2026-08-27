"""webcrack (JS) and wabt (WASM) wrapped as bounded one-shot subprocesses.

Both CLIs are optional and user-provided, exactly like UPX/DIE: a missing tool
degrades to ``capability_unavailable`` rather than blocking readiness. webcrack
needs Node.js 22 or 24; wabt provides ``wasm2wat`` and ``wasm-objdump``.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.bounded_run import (
    InvalidTimeout,
    TimedOut,
    clamp_cli_timeout,
    run_bounded,
)

JsonObject = dict[str, Any]
_MAX_INLINE = 400_000
# Per the tool schema: js.deobfuscate / js.beautify / wasm.* declare le=600,
# js.unpack_bundle le=1200. Each caller passes its own ceiling into _run.
_MAX_TIMEOUT_S = 600.0
_MAX_UNPACK_TIMEOUT_S = 1200.0
_MAX_STDERR = 8000
_MAX_LISTED_FILES = 2000
_MAX_COUNTED_FILES = 50_000
# Output is already sliced. The child still has to load the file, and an
# unattended pass that pointed js.deobfuscate at a captured bundle started
# node on whatever sat on disk -- measured 2,097,152 bytes still reached
# run_bounded. Sixteen mebibytes is enough for a real module and not enough
# to keep a core busy for the rest of the timeout.
_MAX_INPUT_BYTES = 16 * 1024 * 1024
# Every WebAssembly binary opens with these four bytes. Checking them before
# launching wasm2wat / wasm-objdump turns a cryptic tool failure and a wasted
# subprocess into a precise invalid_params -- the same reason the size cap
# refuses input up front rather than handing it to the child.
_WASM_MAGIC = b"\x00asm"
# js.secrets scans the file text for hardcoded credentials. The patterns are
# deliberately the well-known, high-precision provider formats rather than a
# generic entropy heuristic: a match on one of these is almost never a false
# positive, and the labelled type tells the caller what was leaked. Bounded
# like every other scan: a distinct-finding collect cap, a page cap and a
# per-value length clamp so one pathological token cannot blow up the reply.
_MAX_SECRETS_COLLECT = 2000
_MAX_SECRETS_PAGE = 1000
_MAX_SECRET_LEN = 512
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"\bA(?:KIA|SIA)[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    (
        "google_oauth_client_id",
        re.compile(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b"),
    ),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,255}\b")),
    ("stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,99}\b")),
    (
        "jwt",
        re.compile(r"\beyJ[0-9A-Za-z_-]{8,}\.eyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}"),
    ),
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
)


def _capped_file_listing(root: Path, *, cap: int) -> tuple[list[str], int, bool]:
    names: list[str] = []
    total = 0
    has_more = False
    if not root.is_dir():
        return [], 0, False
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if total >= _MAX_COUNTED_FILES:
            has_more = True
            break
        total += 1
        if len(names) < cap:
            names.append(str(path.relative_to(root)))
        else:
            has_more = True
    names.sort()
    return names, total, has_more


class JsReError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _require_existing_file(path: Path, *, missing: str) -> Path:
    """Resolve a regular file, or refuse one that would bind the child unbounded."""
    resolved = path.expanduser()
    if not resolved.is_file():
        raise JsReError("not_found", missing, path=str(resolved))
    try:
        size = int(resolved.stat().st_size)
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    cap = _MAX_INPUT_BYTES
    if size > cap:
        raise JsReError(
            "too_large",
            f"input exceeds the {cap}-byte tool limit",
            path=str(resolved),
            size=size,
            max_file_size=cap,
        )
    return resolved


def _looks_like_wasm(path: Path) -> bool:
    """Whether the file opens with the four-byte WebAssembly magic."""
    try:
        with path.open("rb") as handle:
            return handle.read(4) == _WASM_MAGIC
    except OSError:
        return False


def scan_secrets(path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """Scan a JavaScript (or any text) file for hardcoded credentials.

    Node-free and read-only: the web-RE analog of apk.secrets over the DEX
    string pool, but for a downloaded or minified frontend bundle, which is one
    of the commonest places a live API key leaks. Matches a fixed set of
    well-known provider formats -- AWS access key id, Google API key and OAuth
    client id, Slack, GitHub and Stripe tokens, JWTs, and PEM private-key
    headers -- chosen for precision, so a hit is almost never a false positive
    and its type says what was leaked. It uses no entropy heuristic (a bespoke
    or generic key will be missed) and never launches webcrack, so it needs no
    Node. Each finding is type and value (the matched token, clamped), deduped
    and sorted by (type, value). Returns findings, count, total, offset and
    has_more so a filled page is not read as every secret; total is capped at
    2000 with scan_capped when more may exist. Input over 16 MiB is refused as
    too_large.
    """
    resolved = _require_existing_file(path, missing="input file not found")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise JsReError(
            "backend_error", f"input unreadable: {exc}", path=str(resolved)
        ) from exc
    text = raw.decode("utf-8", errors="replace")
    seen: set[tuple[str, str]] = set()
    scan_more = False
    for label, pattern in _SECRET_PATTERNS:
        if scan_more:
            break
        for match in pattern.finditer(text):
            if len(seen) >= _MAX_SECRETS_COLLECT:
                scan_more = True
                break
            value = match.group(0)[:_MAX_SECRET_LEN]
            seen.add((label, value))
    findings = [
        {"type": label, "value": value} for label, value in sorted(seen)
    ]
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_SECRETS_PAGE))
    window = findings[start : start + cap]
    return {
        "findings": window,
        "count": len(window),
        "total": len(findings),
        "offset": start,
        "has_more": start + len(window) < len(findings),
        "scan_capped": scan_more,
    }


def _run(
    cmd: list[str], *, timeout: float, maximum: float = _MAX_TIMEOUT_S
) -> tuple[str, str, int]:
    try:
        timeout = clamp_cli_timeout(timeout, maximum=maximum)
    except InvalidTimeout as exc:
        raise JsReError("invalid_params", str(exc)) from exc
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        completed = run_bounded(cmd, timeout=timeout, creationflags=creationflags)
    except TimedOut as exc:
        # webcrack runs under node, which the launcher starts as a child, so
        # the deadline has to reach it too.
        raise JsReError(
            "timeout", "tool timed out", timeout=timeout, killed_pids=exc.killed
        ) from exc
    except OSError as exc:
        raise JsReError("backend_error", f"failed to launch {cmd[0]}: {exc}") from exc
    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    return stdout, stderr, int(completed.returncode)


def _bounded_output(text: str, key: str, *, include_bytes: bool) -> JsonObject:
    payload = text.encode("utf-8", errors="replace")
    result: JsonObject = {
        key: payload[:_MAX_INLINE].decode("utf-8", errors="ignore"),
        "truncated": len(payload) > _MAX_INLINE,
    }
    if include_bytes:
        result["bytes"] = len(payload)
    return result


def _note_nonzero_exit(result: JsonObject, *, code: int, stderr: str) -> JsonObject:
    """Say when the tool exited non-zero but still produced output.

    These CLIs are kept on the "return what we got" path on purpose -- webcrack
    exits non-zero on a partial deobfuscation while still emitting usable code,
    and wasm-objdump can print sections before it trips on a later one. But a
    clean pass and a bail-out that happened to print something were otherwise
    indistinguishable: the reply carried no exit status, so an unattended agent
    read a truncated-because-the-tool-died result as the finished article.
    ``tool_failed`` is distinct from ``truncated`` (which is only ever "we cut
    the text at the inline cap"): it means the child itself signalled failure,
    so the output may be incomplete for a reason we cannot see.
    """
    if code != 0:
        result["exit_code"] = code
        result["tool_failed"] = True
        result["stderr"] = stderr[:_MAX_STDERR]
    return result


class JsClient:
    """webcrack-backed JavaScript deobfuscation and bundle unpacking."""

    def __init__(self, executable: Path | None = None) -> None:
        self.executable = executable or _discover_webcrack()

    @property
    def available(self) -> bool:
        return self.executable is not None

    def _require_input(self, path: Path) -> Path:
        if self.executable is None:
            raise JsReError(
                "capability_unavailable", "webcrack is not configured (needs Node 22/24)"
            )
        return _require_existing_file(path, missing="input file not found")

    def deobfuscate(self, path: Path, *, timeout: float = 120.0) -> JsonObject:
        resolved = self._require_input(path)
        stdout, stderr, code = _run(
            [str(self.executable), str(resolved)], timeout=timeout, maximum=_MAX_TIMEOUT_S
        )
        if code != 0 and not stdout:
            raise JsReError(
                "backend_error", "webcrack failed", exit_code=code, stderr=stderr[:_MAX_STDERR]
            )
        return _note_nonzero_exit(
            _bounded_output(stdout, "code", include_bytes=True), code=code, stderr=stderr
        )

    def beautify(self, path: Path, *, timeout: float = 120.0) -> JsonObject:
        # webcrack always unminifies; expose it under a formatting-focused name.
        return self.deobfuscate(path, timeout=timeout)

    def unpack_bundle(
        self,
        path: Path,
        out_dir: Path,
        *,
        timeout: float = 300.0,
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        resolved = self._require_input(path)
        out_dir.mkdir(parents=True, exist_ok=True)
        stdout, stderr, code = _run(
            [str(self.executable), str(resolved), "-o", str(out_dir)],
            timeout=timeout,
            maximum=_MAX_UNPACK_TIMEOUT_S,
        )
        files, file_count, listed_more = _capped_file_listing(out_dir, cap=_MAX_COUNTED_FILES)
        if code != 0 and not files:
            raise JsReError(
                "backend_error",
                "webcrack unpack failed",
                exit_code=code,
                stderr=stderr[:_MAX_STDERR],
            )
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_LISTED_FILES))
        window = files[start : start + cap]
        result: JsonObject = {
            "output_dir": str(out_dir),
            "file_count": file_count,
            "files": window,
            "count": len(window),
            "total": file_count,
            "offset": start,
            "has_more": start + len(window) < file_count,
            "listing_truncated": listed_more,
        }
        return _note_nonzero_exit(result, code=code, stderr=stderr)


class WasmClient:
    """wabt-backed WebAssembly inspection (wasm2wat, wasm-objdump)."""

    def __init__(self, wabt: Path | None = None) -> None:
        self._wasm2wat = _resolve_wabt_tool(wabt, "wasm2wat")
        self._objdump = _resolve_wabt_tool(wabt, "wasm-objdump")

    @property
    def available(self) -> bool:
        return self._wasm2wat is not None

    def _require_input(self, path: Path, tool: Path | None, name: str) -> Path:
        if tool is None:
            raise JsReError("capability_unavailable", f"{name} (wabt) is not configured")
        resolved = _require_existing_file(path, missing="wasm file not found")
        # The size cap runs first (above): an oversized non-module is still
        # refused as too_large, not misreported as a bad-magic file.
        if not _looks_like_wasm(resolved):
            raise JsReError(
                "invalid_params",
                "not a WebAssembly module: missing the \\0asm magic",
                path=str(resolved),
            )
        return resolved

    def wat(self, path: Path, *, timeout: float = 120.0) -> JsonObject:
        resolved = self._require_input(path, self._wasm2wat, "wasm2wat")
        assert self._wasm2wat is not None
        stdout, stderr, code = _run([str(self._wasm2wat), str(resolved)], timeout=timeout)
        if code != 0 and not stdout:
            raise JsReError(
                "backend_error", "wasm2wat failed", exit_code=code, stderr=stderr[:_MAX_STDERR]
            )
        return _note_nonzero_exit(
            _bounded_output(stdout, "wat", include_bytes=True), code=code, stderr=stderr
        )

    def info(self, path: Path, *, timeout: float = 120.0) -> JsonObject:
        resolved = self._require_input(path, self._objdump, "wasm-objdump")
        assert self._objdump is not None
        stdout, stderr, code = _run(
            [str(self._objdump), "-h", "-x", str(resolved)], timeout=timeout
        )
        if code != 0 and not stdout:
            raise JsReError(
                "backend_error", "wasm-objdump failed", exit_code=code, stderr=stderr[:_MAX_STDERR]
            )
        return _note_nonzero_exit(
            _bounded_output(stdout, "objdump", include_bytes=False), code=code, stderr=stderr
        )


def _discover_webcrack() -> Path | None:
    found = shutil.which("webcrack")
    return Path(found) if found else None


def _resolve_wabt_tool(wabt: Path | None, tool: str) -> Path | None:
    exe = tool + (".exe" if os.name == "nt" else "")
    if wabt is not None:
        candidate = wabt if wabt.name.lower().startswith(tool) else wabt / exe
        if candidate.is_file():
            return candidate
        # wabt may point at the bin directory.
        alt = wabt / "bin" / exe
        if alt.is_file():
            return alt
    found = shutil.which(tool)
    return Path(found) if found else None
