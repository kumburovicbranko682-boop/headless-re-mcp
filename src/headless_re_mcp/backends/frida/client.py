from __future__ import annotations

import contextlib
import re
from collections.abc import Callable, Iterable
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeout
from inspect import signature
from threading import Thread
from typing import Any, TypeVar

from headless_re_mcp.core.limits import MAX_WORKFLOW_TIMEOUT

JsonObject = dict[str, Any]
T = TypeVar("T")
_ANDROID_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
# attach / spawn / Java.perform can block forever on a paused debuggee or a
# process without a JIT. 30s matches adb shell and windbg attach: enough for a
# slow USB spawn, short enough that a wedged probe cannot keep a worker.
_PROBE_TIMEOUT_S = 30.0

# Every operation here attaches, works, and detaches in a finally, which is what
# keeps a failed call from leaving an agent resident in someone's process. For
# reads that is invisible, but a hook is meant to outlive the call and does not:
# detaching destroys the session and every script in it. Measured on frida
# 16.5.9 -- ``script.is_destroyed`` is False after load and True right after
# ``session.detach()``. So the reply says so, the way ``attach`` already does,
# rather than reporting a hook that stopped existing before the caller read it.
_PROBE_DISCLOSURE = {
    "persisted": False,
    "note": (
        "probe injection: the template compiled and loaded, then was destroyed when "
        "this session detached, so nothing stays hooked in the target"
    ),
}

_HOOK_TEMPLATES = {
    "noop": "rpc.exports = { ping: function () { return 'pong'; } };",
    # Android Java-layer canned hooks. They no-op on non-ART processes (the
    # script load raises and the caller receives a backend_error envelope).
    "android_ssl_unpin": """
Java.perform(function () {
  try {
    var X509 = Java.use('javax.net.ssl.X509TrustManager');
    var Ctx = Java.use('javax.net.ssl.SSLContext');
    var Trust = Java.registerClass({
      name: 'com.headlessre.TrustAll',
      implements: [X509],
      methods: {
        checkClientTrusted: function () {},
        checkServerTrusted: function () {},
        getAcceptedIssuers: function () { return []; }
      }
    });
    var init = Ctx.init.overload(
      '[Ljavax.net.ssl.KeyManager;',
      '[Ljavax.net.ssl.TrustManager;',
      'java.security.SecureRandom'
    );
    init.implementation = function (km, tm, sr) {
      init.call(this, km, [Trust.$new()], sr);
    };
  } catch (e) {}
});
rpc.exports = { ping: function () { return 'ssl_unpin_loaded'; } };
""",
    "android_crypto_monitor": """
Java.perform(function () {
  try {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function (data) {
      send({ tag: 'crypto', algo: this.getAlgorithm(), len: data.length });
      return this.doFinal(data);
    };
  } catch (e) {}
});
rpc.exports = { ping: function () { return 'crypto_monitor_loaded'; } };
""",
    "android_root_bypass": """
Java.perform(function () {
  try {
    var File = Java.use('java.io.File');
    File.exists.implementation = function () {
      var p = this.getAbsolutePath();
      if (p.indexOf('su') !== -1 || p.indexOf('magisk') !== -1) return false;
      return this.exists();
    };
  } catch (e) {}
});
rpc.exports = { ping: function () { return 'root_bypass_loaded'; } };
""",
}

_ENUM_SCRIPT = """
rpc.exports = {
  modules: function (filter, limit) {
    var all = Process.enumerateModules();
    var items = [];
    var cap = Math.max(0, limit);
    var total = 0;
    for (var i = 0; i < all.length; i++) {
      var m = all[i];
      if (filter && m.name.indexOf(filter) === -1) {
        continue;
      }
      total++;
      if (items.length < cap) {
        items.push({name: m.name, base: m.base.toString(), size: m.size, path: m.path});
      }
    }
    return {modules: items, total: total};
  },
  exports: function (moduleName, filter, limit) {
    var mod = Process.findModuleByName(moduleName);
    if (mod === null) {
      return {found: false, exports: []};
    }
    var all = mod.enumerateExports();
    var items = [];
    for (var i = 0; i < all.length && items.length < limit; i++) {
      var e = all[i];
      if (filter && e.name.indexOf(filter) === -1) {
        continue;
      }
      items.push({name: e.name, address: e.address.toString(), type: e.type});
    }
    return {found: true, module: mod.name, base: mod.base.toString(), exports: items};
  },
  imports: function (moduleName, filter, limit) {
    var mod = Process.findModuleByName(moduleName);
    if (mod === null) {
      return {found: false, imports: []};
    }
    var all = mod.enumerateImports();
    var items = [];
    for (var i = 0; i < all.length && items.length < limit; i++) {
      var e = all[i];
      if (filter && e.name.indexOf(filter) === -1) {
        continue;
      }
      items.push({
        name: e.name,
        type: e.type,
        module: e.module ? e.module : '',
        address: e.address ? e.address.toString() : ''
      });
    }
    return {found: true, module: mod.name, base: mod.base.toString(), imports: items};
  },
  ranges: function (protection, filter, limit) {
    var all = Process.enumerateRanges(protection || 'r--');
    var items = [];
    var cap = Math.max(0, limit);
    var total = 0;
    for (var i = 0; i < all.length; i++) {
      var r = all[i];
      var path = (r.file && r.file.path) ? r.file.path : '';
      if (filter && path.indexOf(filter) === -1) {
        continue;
      }
      total++;
      if (items.length < cap) {
        items.push({
          base: r.base.toString(),
          size: r.size,
          protection: r.protection,
          file: path
        });
      }
    }
    return {ranges: items, total: total};
  },
  scan: function (protection, pattern, maxMatches, maxRanges, maxBytesPerRange) {
    var ranges = Process.enumerateRanges(protection || 'r--');
    var matches = [];
    var scannedRanges = 0;
    var truncated = false;
    for (var i = 0; i < ranges.length; i++) {
      if (scannedRanges >= maxRanges) {
        truncated = true;
        break;
      }
      var r = ranges[i];
      scannedRanges++;
      var size = r.size;
      if (maxBytesPerRange > 0 && size > maxBytesPerRange) {
        size = maxBytesPerRange;
      }
      var found;
      try {
        found = Memory.scanSync(r.base, size, pattern);
      } catch (e) {
        // A range that turned unreadable between enumeration and scan makes
        // scanSync throw; skip it rather than abort the whole scan.
        continue;
      }
      var path = (r.file && r.file.path) ? r.file.path : '';
      for (var j = 0; j < found.length; j++) {
        if (matches.length >= maxMatches) {
          truncated = true;
          break;
        }
        matches.push({
          address: found[j].address.toString(),
          size: found[j].size,
          protection: r.protection,
          file: path
        });
      }
      if (matches.length >= maxMatches) {
        truncated = true;
        break;
      }
    }
    return {matches: matches, scanned_ranges: scannedRanges, truncated: truncated};
  },
  read: function (address, size) {
    return Array.from(new Uint8Array(Memory.readByteArray(ptr(address), size)));
  }
};
"""

_JAVA_SCRIPT = """
rpc.exports = {
  classes: function (filter, limit) {
    var out = [];
    Java.perform(function () {
      try {
        Java.enumerateLoadedClasses({
          onMatch: function (name) {
            if (filter && name.indexOf(filter) === -1) {
              return;
            }
            out.push(name);
            if (out.length >= limit) {
              throw 'headless-re-mcp:class-cap';
            }
          },
          onComplete: function () {}
        });
      } catch (e) {
        if (String(e) !== 'headless-re-mcp:class-cap') {
          throw e;
        }
      }
    });
    return out;
  },
  methods: function (className, filter, limit) {
    var out = [];
    Java.perform(function () {
      var clazz = Java.use(className);
      var methods = clazz.class.getDeclaredMethods();
      for (var i = 0; i < methods.length && out.length < limit; i++) {
        var sig = methods[i].toString();
        if (filter && sig.indexOf(filter) === -1) {
          continue;
        }
        out.push(sig);
      }
    });
    return out;
  },
  instances: function (className, limit, maxFields, filter, maxValue) {
    var out = [];
    Java.perform(function () {
      Java.choose(className, {
        onMatch: function (instance) {
          var rec = { fields: [], field_count: 0, fields_truncated: false };
          try {
            var declared = instance.getClass().getDeclaredFields();
            var kept = 0;
            for (var i = 0; i < declared.length; i++) {
              var f = declared[i];
              var fname = f.getName();
              if (filter && fname.indexOf(filter) === -1) {
                continue;
              }
              rec.field_count += 1;
              if (kept >= maxFields) {
                rec.fields_truncated = true;
                continue;
              }
              var ftype = '';
              try { ftype = f.getType().getName(); } catch (e0) { ftype = ''; }
              var fval;
              try {
                f.setAccessible(true);
                var raw = f.get(instance);
                fval = (raw === null) ? 'null' : ('' + raw);
              } catch (e1) { fval = '<unreadable>'; }
              if (fval.length > maxValue) { fval = fval.substring(0, maxValue); }
              rec.fields.push({ name: fname, type: ftype, value: fval });
              kept += 1;
            }
          } catch (e2) {}
          out.push(rec);
          if (out.length >= limit) {
            return 'stop';
          }
        },
        onComplete: function () {}
      });
    });
    return out;
  },
  statics: function (className, limit, filter, maxValue) {
    var out = [];
    Java.perform(function () {
      var clazz = Java.use(className);
      var Modifier = Java.use('java.lang.reflect.Modifier');
      var declared = clazz.class.getDeclaredFields();
      for (var i = 0; i < declared.length && out.length < limit; i++) {
        var f = declared[i];
        var mods = f.getModifiers();
        if (!Modifier.isStatic(mods)) {
          continue;
        }
        var fname = f.getName();
        if (filter && fname.indexOf(filter) === -1) {
          continue;
        }
        var ftype = '';
        try { ftype = f.getType().getName(); } catch (e0) { ftype = ''; }
        var fval;
        try {
          f.setAccessible(true);
          var raw = f.get(null);
          fval = (raw === null) ? 'null' : ('' + raw);
        } catch (e1) { fval = '<unreadable>'; }
        if (fval.length > maxValue) { fval = fval.substring(0, maxValue); }
        var isFinal = false;
        try { isFinal = Modifier.isFinal(mods); } catch (e2) {}
        out.push({ name: fname, type: ftype, value: fval, is_final: isFinal });
      }
    });
    return out;
  }
};
"""


def _page(values: Any, limit: int) -> tuple[list[Any], bool]:
    """Cut a list to the page size, saying whether anything was left out.

    The enumerations here are asked for one more than the page so this can tell
    "that is all there is" from "that is all you asked for" without counting the
    rest. A caller reading `count` alone cannot tell those apart, and the ones
    that matter -- which classes are loaded, which exports a module has -- are
    exactly the ones an agent draws conclusions from.
    """
    items = list(values or [])
    if len(items) > limit:
        return items[:limit], True
    return items, False


def _require_module_name(module_name: str) -> str:
    if not isinstance(module_name, str) or not module_name.strip():
        raise FridaError("invalid_params", "module_name is required")
    return module_name.strip()


def _check_read_bounds(address: int, size: int) -> None:
    """Reject a bad size or pointer before any session is attached.

    address is typed int in the MCP schema, but the agent transport calls
    handlers with no pydantic validation, so a float/str/negative value can
    reach here and be handed to ptr() in the injected JS. Reject anything that
    is not a real pointer (a non-int -- bool included -- or outside the 64-bit
    range) with invalid_params, the same strict shape the size check uses.
    """
    if type(size) is not int or not 1 <= size <= 256 * 1024:
        raise FridaError("invalid_params", "size must be 1..262144")
    if type(address) is not int or not 0 <= address < 2**64:
        raise FridaError("invalid_params", "address must be an integer in [0, 2**64)")


_PROTECTION_RE = re.compile(r"^[r-][w-][x-]$")


def _normalize_protection(protection: str) -> str:
    """Validate the enumerateRanges protection mask before it reaches the agent.

    Frida takes a three-character r/w/x mask where '-' is a wildcard, so 'r--'
    means "at least readable" (the useful default -- the regions memory.read can
    actually touch) and 'rw-' narrows to writable ones (where a decrypted secret
    lands). The MCP schema constrains it, but the agent transport skips pydantic,
    so a junk string could otherwise be handed to Process.enumerateRanges;
    reject anything off the mask as invalid_params rather than let it through.
    """
    if not isinstance(protection, str):
        raise FridaError("invalid_params", "protection must be a string like 'r--'")
    value = protection.strip()
    if not _PROTECTION_RE.match(value):
        raise FridaError(
            "invalid_params",
            "protection must match [r-][w-][x-], e.g. 'r--', 'rw-', 'rwx', '---'",
            protection=protection,
        )
    return value


_MAX_JAVA_FIELD_VALUE = 512


def _shape_java_field(entry: Any) -> JsonObject | None:
    """Normalise one reflected field into {name, type, value[, is_final]}.

    The agent already caps the value length, but the transport hands whatever it
    returned straight through, so re-bound it here: drop a non-dict row, re-cut
    the value to the ceiling (marking value_truncated), and carry is_final only
    when the agent supplied it (statics do; instance fields do not).
    """
    if not isinstance(entry, dict):
        return None
    value = str(entry.get("value", ""))
    row: JsonObject = {
        "name": str(entry.get("name", "")),
        "type": str(entry.get("type", "")),
        "value": value[:_MAX_JAVA_FIELD_VALUE],
    }
    if len(value) > _MAX_JAVA_FIELD_VALUE:
        row["value_truncated"] = True
    if "is_final" in entry:
        row["is_final"] = bool(entry.get("is_final"))
    return row


def _shape_java_instance(item: Any, max_fields: int) -> JsonObject:
    """Normalise one Java.choose record into {fields, field_count, fields_truncated}."""
    if not isinstance(item, dict):
        return {"fields": [], "field_count": 0, "fields_truncated": False}
    raw_fields = item.get("fields")
    fields: list[JsonObject] = []
    for entry in list(raw_fields or [])[: max(1, int(max_fields))]:
        row = _shape_java_field(entry)
        if row is not None:
            fields.append(row)
    field_count = item.get("field_count")
    return {
        "fields": fields,
        "field_count": int(field_count) if isinstance(field_count, int) else len(fields),
        "fields_truncated": bool(item.get("fields_truncated")),
    }


def _shape_ranges(raw: Any, capped: int) -> JsonObject:
    if isinstance(raw, dict):
        held = list(raw.get("ranges") or [])
        total = int(raw.get("total") or len(held))
    else:
        held = list(raw or [])
        total = len(held)
    items = [
        {
            "base": str(item.get("base", "")),
            "size": int(item.get("size", 0) or 0),
            "protection": str(item.get("protection", "")),
            "file": str(item.get("file", "")),
        }
        for item in held[:capped]
        if isinstance(item, dict)
    ]
    return {
        "ranges": items,
        "count": len(items),
        "total": total,
        "has_more": total > len(items),
    }


# frida.memory.scan runs Memory.scanSync over the ranges a protection mask
# selects. scanSync is native and fast, but the address space can be huge, so the
# agent is handed hard ceilings: how many matches to collect, how many ranges to
# visit, and how many bytes of any one (possibly multi-GB) mapping to scan -- so
# even the local path, which has no probe deadline, cannot run away. truncated in
# the reply says a ceiling was hit and there may be more.
_MAX_SCAN_MATCHES = 1024
_MAX_SCAN_RANGES = 4096
_MAX_SCAN_BYTES_PER_RANGE = 128 * 1024 * 1024
_MAX_SCAN_PATTERN_BYTES = 1024
_HEX_TOKEN_RE = re.compile(r"^([0-9A-Fa-f]{2}|\?\?)$")


def _check_scan_pattern(pattern: str, pattern_type: str) -> str:
    """Turn the caller's needle into a Frida match pattern, or reject it.

    Two entry forms so the common case stays ergonomic and the binary case stays
    possible: ``text`` utf-8 encodes the string to a byte pattern (find a known
    token or error message in memory), and ``hex`` takes a Frida-style pattern of
    space-separated byte pairs with ``??`` wildcards (find a struct signature or
    magic). The MCP schema constrains both, but the agent transport skips
    pydantic, so everything is re-validated here before it reaches scanSync:
    a hex token off ``[0-9a-f]{2}|??`` or an all-wildcard pattern (which would
    match everywhere) is invalid_params, as is an over-long needle.
    """
    if not isinstance(pattern, str) or not pattern.strip():
        raise FridaError("invalid_params", "pattern is required")
    ptype = pattern_type.strip().lower() if isinstance(pattern_type, str) else ""
    if ptype not in ("text", "hex"):
        raise FridaError("invalid_params", "pattern_type must be 'text' or 'hex'")
    if ptype == "text":
        data = pattern.encode("utf-8")
        if len(data) > _MAX_SCAN_PATTERN_BYTES:
            raise FridaError(
                "invalid_params",
                f"pattern too long (> {_MAX_SCAN_PATTERN_BYTES} bytes)",
            )
        return " ".join(f"{byte:02x}" for byte in data)
    tokens = pattern.replace(",", " ").split()
    if len(tokens) > _MAX_SCAN_PATTERN_BYTES:
        raise FridaError(
            "invalid_params", f"pattern too long (> {_MAX_SCAN_PATTERN_BYTES} bytes)"
        )
    concrete = 0
    normalized: list[str] = []
    for token in tokens:
        if not _HEX_TOKEN_RE.match(token):
            raise FridaError(
                "invalid_params",
                f"invalid hex token {token!r}; use byte pairs (e.g. 'de ad') or '??'",
            )
        if token != "??":
            concrete += 1
        normalized.append(token.lower())
    if concrete == 0:
        raise FridaError(
            "invalid_params", "hex pattern needs at least one concrete byte"
        )
    return " ".join(normalized)


def _shape_scan(raw: Any, capped: int) -> JsonObject:
    if not isinstance(raw, dict):
        raise FridaError("backend_error", "unexpected frida scan payload")
    held = list(raw.get("matches") or [])
    items = [
        {
            "address": str(item.get("address", "")),
            "size": int(item.get("size", 0) or 0),
            "protection": str(item.get("protection", "")),
            "file": str(item.get("file", "")),
        }
        for item in held[:capped]
        if isinstance(item, dict)
    ]
    return {
        "matches": items,
        "count": len(items),
        "scanned_ranges": int(raw.get("scanned_ranges") or 0),
        "truncated": bool(raw.get("truncated")),
    }


def _shape_modules(raw: Any, capped: int) -> JsonObject:
    if isinstance(raw, dict):
        held = list(raw.get("modules") or [])
        total = int(raw.get("total") or len(held))
    else:
        held = list(raw or [])
        total = len(held)
    items = [
        {
            "name": str(item.get("name", "")),
            "base": str(item.get("base", "")),
            "size": int(item.get("size", 0) or 0),
            "path": str(item.get("path", "")),
        }
        for item in held[:capped]
        if isinstance(item, dict)
    ]
    return {
        "modules": items,
        "count": len(items),
        "total": total,
        "has_more": total > len(items),
    }


def _shape_exports(raw: Any, module_name: str, capped: int) -> JsonObject:
    if not isinstance(raw, dict):
        raise FridaError("backend_error", "unexpected frida exports payload")
    page, has_more = _page(list(raw.get("exports") or []), capped)
    items = []
    for item in page:
        if not isinstance(item, dict):
            continue
        items.append(
            {
                "name": str(item.get("name", "")),
                "address": str(item.get("address", "")),
                "type": str(item.get("type", "")),
            }
        )
    return {
        "found": bool(raw.get("found")),
        "module": str(raw.get("module") or module_name),
        "base": str(raw.get("base") or ""),
        "exports": items,
        "count": len(items),
        "has_more": has_more,
    }


def _shape_imports(raw: Any, module_name: str, capped: int) -> JsonObject:
    if not isinstance(raw, dict):
        raise FridaError("backend_error", "unexpected frida imports payload")
    page, has_more = _page(list(raw.get("imports") or []), capped)
    items = []
    for item in page:
        if not isinstance(item, dict):
            continue
        items.append(
            {
                "name": str(item.get("name", "")),
                "type": str(item.get("type", "")),
                "module": str(item.get("module", "")),
                "address": str(item.get("address", "")),
            }
        )
    return {
        "found": bool(raw.get("found")),
        "module": str(raw.get("module") or module_name),
        "base": str(raw.get("base") or ""),
        "imports": items,
        "count": len(items),
        "has_more": has_more,
    }


class FridaError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _is_timeout(exc: BaseException) -> bool:
    name = type(exc).__name__.lower()
    return "timeout" in name or "timed out" in str(exc).lower()


def _accepts_timeout(func: Any) -> bool:
    """Whether the callable names ``timeout`` — not merely ``**kwargs``.

    Frida's ``spawn`` takes ``**kwargs`` for aux options; passing a deadline
    there would be a spawn argument, not a hang bound.
    """
    target = getattr(func, "__func__", func)
    try:
        params = signature(target).parameters
    except (TypeError, ValueError):
        return False
    return "timeout" in params


def _bound_timeout(timeout: float) -> float:
    value = float(timeout)
    if value <= 0:
        raise FridaError("invalid_params", "timeout must be positive")
    return min(value, MAX_WORKFLOW_TIMEOUT)


def _timeout_error(timeout: float) -> FridaError:
    return FridaError("timeout", f"frida did not respond within {timeout:g}s")


def _detach_all(sessions: list[Any]) -> None:
    while sessions:
        session = sessions.pop()
        with contextlib.suppress(Exception):
            session.detach()


def _kill_spawned(device: Any, pids: list[int]) -> None:
    while pids:
        pid = pids.pop()
        with contextlib.suppress(Exception):
            device.kill(pid)


def _run_deadline(
    work: Callable[[], T],
    *,
    timeout: float,
    on_timeout: Callable[[], None] | None = None,
) -> T:
    """Bound a Frida native call that may not accept a timeout argument.

    ``Future.result(timeout=)`` is the same outer deadline the web runner uses
    when a driver call can never return. The worker is a daemon so a still-stuck
    attach cannot keep the process alive after the caller has moved on.
    """
    done: Future[T] = Future()

    def run() -> None:
        try:
            done.set_result(work())
        except BaseException as exc:  # noqa: BLE001 - handed to the caller
            if not done.done():
                done.set_exception(exc)

    thread = Thread(target=run, name="frida-deadline", daemon=True)
    thread.start()
    try:
        return done.result(timeout=timeout)
    except FutureTimeout as exc:
        if on_timeout is not None:
            with contextlib.suppress(Exception):
                on_timeout()
        raise _timeout_error(timeout) from exc


def _invoke(method: Any, *args: Any, timeout: float, **kwargs: Any) -> Any:
    extra = dict(kwargs)
    if _accepts_timeout(method):
        extra["timeout"] = timeout
    return method(*args, **extra)


class FridaClient:
    def __init__(self) -> None:
        self._frida: Any = None
        self._available = False
        try:
            import frida

            self._frida = frida
            self._available = True
        except Exception:
            self._frida = None
            self._available = False

    @property
    def available(self) -> bool:
        return self._available

    # ------------------------------------------------------------------
    # Local-device operations (unchanged contract: one allowed pid).
    # These serve PE sessions whose debuggee runs on the local machine.
    # ------------------------------------------------------------------
    def attach(self, pid: int, *, allowed_pid: int,
               timeout: float = _PROBE_TIMEOUT_S) -> JsonObject:
        if not self._available or self._frida is None:
            raise FridaError("capability_unavailable", "frida Python module is not installed")
        if type(pid) is not int or pid <= 0:
            raise FridaError("invalid_params", "pid must be a positive integer")
        if pid != allowed_pid:
            raise FridaError(
                "permission_denied",
                "frida attach limited to session debuggee pid",
                pid=pid,
                allowed_pid=allowed_pid,
            )
        session = self._attach_local(pid, timeout=timeout)
        try:
            return {
                "pid": pid,
                "attached": True,
                "device": "local",
                "note": "probe attach; detached immediately",
            }
        finally:
            with contextlib.suppress(Exception):
                session.detach()

    def modules(
        self, pid: int, *, allowed_pid: int, limit: int = 64, name_filter: str = ""
    ) -> JsonObject:
        self._require(pid, allowed_pid)
        session = self._attach_local(pid)
        try:
            return self._run_enum(
                session, kind="modules", limit=limit, name_filter=name_filter
            )
        finally:
            with contextlib.suppress(Exception):
                session.detach()

    def exports(
        self,
        pid: int,
        module_name: str,
        *,
        allowed_pid: int,
        limit: int = 64,
        name_filter: str = "",
    ) -> JsonObject:
        self._require(pid, allowed_pid)
        module = _require_module_name(module_name)
        session = self._attach_local(pid)
        try:
            return self._run_enum(
                session,
                kind="exports",
                module_name=module,
                limit=limit,
                name_filter=name_filter,
            )
        finally:
            with contextlib.suppress(Exception):
                session.detach()

    def imports(
        self,
        pid: int,
        module_name: str,
        *,
        allowed_pid: int,
        limit: int = 64,
        name_filter: str = "",
    ) -> JsonObject:
        self._require(pid, allowed_pid)
        module = _require_module_name(module_name)
        session = self._attach_local(pid)
        try:
            return self._run_enum(
                session,
                kind="imports",
                module_name=module,
                limit=limit,
                name_filter=name_filter,
            )
        finally:
            with contextlib.suppress(Exception):
                session.detach()

    def ranges(
        self,
        pid: int,
        *,
        allowed_pid: int,
        protection: str = "r--",
        limit: int = 64,
        name_filter: str = "",
    ) -> JsonObject:
        self._require(pid, allowed_pid)
        prot = _normalize_protection(protection)
        session = self._attach_local(pid)
        try:
            return self._run_enum(
                session,
                kind="ranges",
                protection=prot,
                limit=limit,
                name_filter=name_filter,
            )
        finally:
            with contextlib.suppress(Exception):
                session.detach()

    def scan(
        self,
        pid: int,
        *,
        allowed_pid: int,
        pattern: str,
        pattern_type: str = "text",
        protection: str = "r--",
        limit: int = 64,
    ) -> JsonObject:
        self._require(pid, allowed_pid)
        prot = _normalize_protection(protection)
        scan_pattern = _check_scan_pattern(pattern, pattern_type)
        session = self._attach_local(pid)
        try:
            return self._run_enum(
                session,
                kind="scan",
                protection=prot,
                scan_pattern=scan_pattern,
                limit=limit,
            )
        finally:
            with contextlib.suppress(Exception):
                session.detach()

    def memory_read(
        self, pid: int, address: int, size: int, *, allowed_pid: int
    ) -> JsonObject:
        self._require(pid, allowed_pid)
        _check_read_bounds(address, size)
        session = self._attach_local(pid)
        try:
            return self._run_enum(session, kind="read", address=address, size=size)
        finally:
            with contextlib.suppress(Exception):
                session.detach()

    def _run_enum(
        self,
        session: Any,
        *,
        kind: str,
        module_name: str = "",
        address: int = 0,
        size: int = 0,
        limit: int = 64,
        name_filter: str = "",
        protection: str = "r--",
        scan_pattern: str = "",
    ) -> JsonObject:
        """Load the enumeration agent into an attached session and run one query.

        Shared by the local (PE debuggee) and device (Android/USB/remote) paths
        so a native module's exports/imports and a raw memory read behave the
        same whichever process the session is bound to. The caller owns attach
        and detach; this only creates the script, calls the one RPC, and shapes
        the reply. A substring ``name_filter`` is applied in-agent before the
        cap -- the only way to reach a symbol past the limit, since there is no
        offset -- mirroring frida.java.classes / methods.
        """
        script = session.create_script(_ENUM_SCRIPT)
        script.load()
        needle = name_filter.strip() if isinstance(name_filter, str) else ""
        if kind == "modules":
            capped = max(1, min(int(limit), 256))
            return _shape_modules(script.exports_sync.modules(needle, capped), capped)
        if kind == "ranges":
            capped = max(1, min(int(limit), 256))
            return _shape_ranges(
                script.exports_sync.ranges(protection, needle, capped), capped
            )
        if kind == "scan":
            capped = max(1, min(int(limit), _MAX_SCAN_MATCHES))
            return _shape_scan(
                script.exports_sync.scan(
                    protection,
                    scan_pattern,
                    capped,
                    _MAX_SCAN_RANGES,
                    _MAX_SCAN_BYTES_PER_RANGE,
                ),
                capped,
            )
        if kind == "exports":
            capped = max(1, min(int(limit), 512))
            raw = script.exports_sync.exports(module_name, needle, capped + 1)
            return _shape_exports(raw, module_name, capped)
        if kind == "imports":
            capped = max(1, min(int(limit), 512))
            raw = script.exports_sync.imports(module_name, needle, capped + 1)
            return _shape_imports(raw, module_name, capped)
        if kind == "read":
            try:
                data = bytes(script.exports_sync.read(int(address), int(size)))
            except FridaError:
                raise
            except Exception as exc:  # noqa: BLE001
                # Reading an unmapped or protected address makes Memory.
                # readByteArray throw in the agent, surfacing as an RPC error.
                # That is the caller's address being unreadable, not an internal
                # fault, so give it a clean backend_error instead of letting a
                # raw exception bubble up as internal_error.
                raise FridaError(
                    "backend_error",
                    f"could not read {size} bytes at {address:#x}; "
                    "the address may be unmapped or protected",
                    address=address,
                    size=size,
                ) from exc
            return {
                "address": address,
                "size": size,
                "encoding": "hex",
                "data": data.hex(),
            }
        raise FridaError("invalid_params", f"unknown enum kind {kind!r}")

    def hook_template(self, pid: int, template: str, *, allowed_pid: int,
                      timeout: float = _PROBE_TIMEOUT_S) -> JsonObject:
        self._require(pid, allowed_pid)
        source = _HOOK_TEMPLATES.get(template)
        if source is None:
            raise FridaError(
                "invalid_params",
                "unknown hook template",
                template=template,
                allowed=sorted(_HOOK_TEMPLATES),
            )
        deadline = _bound_timeout(timeout)
        sessions: list[Any] = []

        def work() -> JsonObject:
            session = _invoke(self._frida.attach, pid, timeout=deadline)
            sessions.append(session)
            try:
                script = session.create_script(source)
                script.load()
                return {
                    "pid": pid,
                    "template": template,
                    "loaded": True,
                    "device": "local",
                    **_PROBE_DISCLOSURE,
                }
            finally:
                with contextlib.suppress(Exception):
                    session.detach()

        try:
            return _run_deadline(work, timeout=deadline, on_timeout=lambda: _detach_all(sessions))
        except FridaError:
            raise
        except Exception as exc:  # noqa: BLE001
            if _is_timeout(exc):
                _detach_all(sessions)
                raise _timeout_error(deadline) from exc
            raise

    def _attach_local(self, pid: int, *, timeout: float = _PROBE_TIMEOUT_S) -> Any:
        deadline = _bound_timeout(timeout)
        sessions: list[Any] = []

        def work() -> Any:
            session = _invoke(self._frida.attach, pid, timeout=deadline)
            sessions.append(session)
            return session

        try:
            return _run_deadline(
                work, timeout=deadline, on_timeout=lambda: _detach_all(sessions)
            )
        except FridaError:
            raise
        except Exception as exc:  # noqa: BLE001
            if _is_timeout(exc):
                _detach_all(sessions)
                raise _timeout_error(deadline) from exc
            raise FridaError("backend_error", f"attach failed: {exc}", pid=pid) from exc

    def _require(self, pid: int, allowed_pid: int) -> None:
        if pid != allowed_pid:
            raise FridaError("permission_denied", "pid not allowed", pid=pid)
        if not self._available or self._frida is None:
            raise FridaError("capability_unavailable", "frida Python module is not installed")

    # ------------------------------------------------------------------
    # Device-aware operations (USB / emulator / remote). The single-pid
    # check is generalised to a per-session allow-set rather than removed:
    # callers must pass the set of pids this session is authorised to touch.
    # ------------------------------------------------------------------
    def _need(self) -> Any:
        if not self._available or self._frida is None:
            raise FridaError("capability_unavailable", "frida Python module is not installed")
        return self._frida

    def _resolve_device(self, device_id: str | None) -> Any:
        frida = self._need()
        try:
            if device_id in (None, "", "local"):
                return frida.get_local_device()
            if device_id == "usb":
                return frida.get_usb_device(timeout=5)
            if isinstance(device_id, str) and (":" in device_id):
                # Reuse an already-registered remote device. Re-adding it on
                # every call churns frida's device manager for what is meant to
                # be a stable connection held for the life of the session.
                mgr = frida.get_device_manager()
                with contextlib.suppress(Exception):
                    return mgr.get_device(device_id, timeout=1)
                return mgr.add_remote_device(device_id)
            return frida.get_device(device_id, timeout=5)
        except FridaError:
            raise
        except Exception as exc:  # noqa: BLE001 - frida raises many device errors
            raise FridaError(
                "not_found", f"frida device unavailable: {exc}", device_id=device_id
            ) from exc

    def enumerate_devices(self) -> JsonObject:
        frida = self._need()
        try:
            devices = _run_deadline(frida.enumerate_devices, timeout=30.0)
        except Exception as exc:  # noqa: BLE001
            raise FridaError("backend_error", f"failed to enumerate devices: {exc}") from exc
        items = [
            {"id": str(dev.id), "name": str(dev.name), "type": str(dev.type)}
            for dev in devices
        ]
        return {"devices": items, "count": len(items)}

    def add_remote_device(self, endpoint: str) -> JsonObject:
        frida = self._need()
        try:
            mgr = frida.get_device_manager()
            device = None
            with contextlib.suppress(Exception):
                device = mgr.get_device(endpoint, timeout=1)
            if device is None:
                device = mgr.add_remote_device(endpoint)
        except Exception as exc:  # noqa: BLE001
            raise FridaError(
                "backend_error", f"failed to add remote device: {exc}", endpoint=endpoint
            ) from exc
        return {"id": str(device.id), "name": str(device.name), "type": str(device.type)}

    def applications(
        self, device_id: str | None, *, limit: int = 256, name_filter: str = ""
    ) -> JsonObject:
        device = self._resolve_device(device_id)
        try:
            apps = _run_deadline(device.enumerate_applications, timeout=30.0)
        except Exception as exc:  # noqa: BLE001
            raise FridaError("backend_error", f"failed to enumerate applications: {exc}") from exc
        capped = max(1, min(int(limit), 1000))
        rows = [
            {
                "identifier": str(app.identifier),
                "name": str(app.name),
                "pid": int(getattr(app, "pid", 0) or 0),
            }
            for app in apps
        ]
        # A case-insensitive substring over identifier or name, applied before
        # the cap so a target app past the first `limit` on a full device is
        # reachable (there is no offset). total then reflects the match count.
        # Python-side like device.packages, not an in-agent JS filter.
        needle = name_filter.strip().lower() if isinstance(name_filter, str) else ""
        if needle:
            rows = [
                row
                for row in rows
                if needle in str(row["identifier"]).lower()
                or needle in str(row["name"]).lower()
            ]
        items = rows[:capped]
        return {
            "applications": items,
            "count": len(items),
            "total": len(rows),
            "has_more": len(rows) > capped,
        }

    def processes(
        self, device_id: str | None, *, limit: int = 256, name_filter: str = ""
    ) -> JsonObject:
        """Running processes on the device, in frida's own pid namespace.

        frida.applications lists what is *installed*; this lists what is
        *running* -- every live process, not just the app ones -- via frida's
        own ``enumerate_processes``, so a system daemon, a native helper or an
        already-forked app becomes an attachable target. The pid returned is the
        one frida.attach/hook consume directly (frida's pid space, the same
        device this session is bound to), which is why this lives on the frida
        line rather than only device.processes (adb ``ps``, Android-only, an
        adb-serial pid).
        """
        device = self._resolve_device(device_id)
        try:
            procs = _run_deadline(device.enumerate_processes, timeout=30.0)
        except Exception as exc:  # noqa: BLE001
            raise FridaError("backend_error", f"failed to enumerate processes: {exc}") from exc
        capped = max(1, min(int(limit), 1000))
        rows: list[JsonObject] = [
            {
                "pid": int(getattr(proc, "pid", 0) or 0),
                "name": str(getattr(proc, "name", "")),
            }
            for proc in procs
        ]
        # A case-insensitive substring over the process name, applied before the
        # cap so a target past the first `limit` on a busy device is reachable
        # (there is no offset, matching frida.applications). total then reflects
        # the match count. Python-side like applications, not an in-agent filter.
        needle = name_filter.strip().lower() if isinstance(name_filter, str) else ""
        if needle:
            rows = [row for row in rows if needle in str(row["name"]).lower()]
        # Ascending pid so the capped page is stable across calls.
        rows.sort(key=lambda row: int(row["pid"]))
        items = rows[:capped]
        return {
            "processes": items,
            "count": len(items),
            "total": len(rows),
            "has_more": len(rows) > capped,
        }

    def spawn(
        self,
        device_id: str | None,
        package: str,
        *,
        timeout: float = _PROBE_TIMEOUT_S,
    ) -> JsonObject:
        device = self._resolve_device(device_id)
        if not isinstance(package, str) or not package.strip():
            raise FridaError("invalid_params", "package is required")
        pkg = package.strip()
        if not _ANDROID_PACKAGE_RE.match(pkg):
            raise FridaError(
                "invalid_params",
                "package must be an Android package id",
                package=pkg,
            )
        deadline = _bound_timeout(timeout)
        pids: list[int] = []

        def work() -> int:
            try:
                spawned = int(_invoke(device.spawn, pkg, timeout=deadline))
            except Exception as exc:  # noqa: BLE001
                if _is_timeout(exc):
                    raise _timeout_error(deadline) from exc
                raise FridaError("backend_error", f"spawn failed: {exc}", package=pkg) from exc
            pids.append(spawned)
            try:
                _invoke(device.resume, spawned, timeout=deadline)
            except FridaError:
                with contextlib.suppress(Exception):
                    device.kill(spawned)
                raise
            except Exception as exc:  # noqa: BLE001
                with contextlib.suppress(Exception):
                    device.kill(spawned)
                if _is_timeout(exc):
                    raise _timeout_error(deadline) from exc
                raise FridaError(
                    "backend_error",
                    f"spawned pid {spawned} but resume failed; process was killed: {exc}",
                    package=pkg,
                    pid=spawned,
                ) from exc
            return spawned

        try:
            pid = _run_deadline(
                work, timeout=deadline, on_timeout=lambda: _kill_spawned(device, pids)
            )
        except FridaError:
            raise
        except Exception as exc:  # noqa: BLE001
            _kill_spawned(device, pids)
            if _is_timeout(exc):
                raise _timeout_error(deadline) from exc
            raise FridaError("backend_error", f"spawn failed: {exc}", package=pkg) from exc
        return {"package": pkg, "pid": pid, "device": str(device_id or "local")}

    def java_enumerate(
        self,
        device_id: str | None,
        pid: int,
        *,
        allowed_pids: Iterable[int],
        mode: str,
        class_name: str | None = None,
        name_filter: str | None = None,
        limit: int = 200,
        max_fields: int = 64,
        timeout: float = _PROBE_TIMEOUT_S,
    ) -> JsonObject:
        self._authorize(pid, allowed_pids)
        device = self._resolve_device(device_id)
        capped = max(1, min(int(limit), 2000))
        deadline = _bound_timeout(timeout)
        sessions: list[Any] = []

        def work() -> JsonObject:
            try:
                session = _invoke(device.attach, pid, timeout=deadline)
            except Exception as exc:  # noqa: BLE001
                if _is_timeout(exc):
                    raise _timeout_error(deadline) from exc
                raise FridaError("backend_error", f"attach failed: {exc}", pid=pid) from exc
            sessions.append(session)
            try:
                script = session.create_script(_JAVA_SCRIPT)
                script.load()
                if mode == "classes":
                    values, has_more = _page(
                        script.exports_sync.classes(name_filter or "", capped + 1), capped
                    )
                    return {"classes": values, "count": len(values), "has_more": has_more}
                if mode == "methods":
                    if not class_name:
                        raise FridaError("invalid_params", "class_name is required")
                    # Filter in-agent before the cap, like classes: a target
                    # method (doFinal, checkLicense) on a class with hundreds of
                    # declared methods is findable rather than buried, and there
                    # is no offset to page past the cap otherwise.
                    values, has_more = _page(
                        script.exports_sync.methods(class_name, name_filter or "", capped + 1),
                        capped,
                    )
                    return {
                        "class_name": class_name,
                        "methods": values,
                        "count": len(values),
                        "has_more": has_more,
                    }
                if mode == "instances":
                    if not class_name:
                        raise FridaError("invalid_params", "class_name is required")
                    # Java.choose walks the live heap; ask for one past the cap to
                    # tell "that is every instance" from "that is the page you
                    # asked for", and reflect declared fields into a snapshot.
                    max_f = max(1, min(int(max_fields), 256))
                    raw = script.exports_sync.instances(
                        class_name, capped + 1, max_f, name_filter or "", _MAX_JAVA_FIELD_VALUE
                    )
                    values, has_more = _page(raw, capped)
                    return {
                        "class_name": class_name,
                        "instances": [_shape_java_instance(item, max_f) for item in values],
                        "count": len(values),
                        "has_more": has_more,
                    }
                if mode == "statics":
                    if not class_name:
                        raise FridaError("invalid_params", "class_name is required")
                    # Static fields need no live instance: reflect them off the
                    # Class with f.get(null), the home of hardcoded keys / URLs a
                    # utility class holds when nothing of it exists on the heap.
                    raw = script.exports_sync.statics(
                        class_name, capped + 1, name_filter or "", _MAX_JAVA_FIELD_VALUE
                    )
                    values, has_more = _page(raw, capped)
                    fields = [
                        row for row in (_shape_java_field(item) for item in values) if row
                    ]
                    return {
                        "class_name": class_name,
                        "fields": fields,
                        "count": len(fields),
                        "has_more": has_more,
                    }
                raise FridaError(
                    "invalid_params", "mode must be classes, methods, instances or statics"
                )
            finally:
                with contextlib.suppress(Exception):
                    session.detach()

        try:
            return _run_deadline(
                work, timeout=deadline, on_timeout=lambda: _detach_all(sessions)
            )
        except FridaError:
            raise
        except Exception as exc:  # noqa: BLE001
            _detach_all(sessions)
            if _is_timeout(exc):
                raise _timeout_error(deadline) from exc
            raise FridaError("backend_error", f"java enumeration failed: {exc}") from exc

    # The native-enumeration analogue of java_enumerate: modules / exports /
    # imports / memory reads against an authorized *device* pid, not just the
    # local debuggee. Enumerating a .so's symbols (SSL_write, JNI_OnLoad) and
    # reading device memory is the first native step on an Android target, and
    # without these it was impossible once a session was bound to USB/remote.
    def modules_device(
        self,
        device_id: str | None,
        pid: int,
        *,
        allowed_pids: Iterable[int],
        limit: int = 64,
        name_filter: str = "",
        timeout: float = _PROBE_TIMEOUT_S,
    ) -> JsonObject:
        self._authorize(pid, allowed_pids)
        device = self._resolve_device(device_id)
        return self._enum_on_device(
            device, pid, kind="modules", limit=limit, name_filter=name_filter, timeout=timeout
        )

    def exports_device(
        self,
        device_id: str | None,
        pid: int,
        module_name: str,
        *,
        allowed_pids: Iterable[int],
        limit: int = 64,
        name_filter: str = "",
        timeout: float = _PROBE_TIMEOUT_S,
    ) -> JsonObject:
        self._authorize(pid, allowed_pids)
        module = _require_module_name(module_name)
        device = self._resolve_device(device_id)
        return self._enum_on_device(
            device,
            pid,
            kind="exports",
            module_name=module,
            limit=limit,
            name_filter=name_filter,
            timeout=timeout,
        )

    def imports_device(
        self,
        device_id: str | None,
        pid: int,
        module_name: str,
        *,
        allowed_pids: Iterable[int],
        limit: int = 64,
        name_filter: str = "",
        timeout: float = _PROBE_TIMEOUT_S,
    ) -> JsonObject:
        self._authorize(pid, allowed_pids)
        module = _require_module_name(module_name)
        device = self._resolve_device(device_id)
        return self._enum_on_device(
            device,
            pid,
            kind="imports",
            module_name=module,
            limit=limit,
            name_filter=name_filter,
            timeout=timeout,
        )

    def ranges_device(
        self,
        device_id: str | None,
        pid: int,
        *,
        allowed_pids: Iterable[int],
        protection: str = "r--",
        limit: int = 64,
        name_filter: str = "",
        timeout: float = _PROBE_TIMEOUT_S,
    ) -> JsonObject:
        self._authorize(pid, allowed_pids)
        prot = _normalize_protection(protection)
        device = self._resolve_device(device_id)
        return self._enum_on_device(
            device,
            pid,
            kind="ranges",
            protection=prot,
            limit=limit,
            name_filter=name_filter,
            timeout=timeout,
        )

    def scan_device(
        self,
        device_id: str | None,
        pid: int,
        *,
        allowed_pids: Iterable[int],
        pattern: str,
        pattern_type: str = "text",
        protection: str = "r--",
        limit: int = 64,
        timeout: float = _PROBE_TIMEOUT_S,
    ) -> JsonObject:
        self._authorize(pid, allowed_pids)
        prot = _normalize_protection(protection)
        scan_pattern = _check_scan_pattern(pattern, pattern_type)
        device = self._resolve_device(device_id)
        return self._enum_on_device(
            device,
            pid,
            kind="scan",
            protection=prot,
            scan_pattern=scan_pattern,
            limit=limit,
            timeout=timeout,
        )

    def memory_read_device(
        self,
        device_id: str | None,
        pid: int,
        address: int,
        size: int,
        *,
        allowed_pids: Iterable[int],
        timeout: float = _PROBE_TIMEOUT_S,
    ) -> JsonObject:
        self._authorize(pid, allowed_pids)
        _check_read_bounds(address, size)
        device = self._resolve_device(device_id)
        return self._enum_on_device(
            device, pid, kind="read", address=address, size=size, timeout=timeout
        )

    def _enum_on_device(
        self,
        device: Any,
        pid: int,
        *,
        kind: str,
        module_name: str = "",
        address: int = 0,
        size: int = 0,
        limit: int = 64,
        name_filter: str = "",
        protection: str = "r--",
        scan_pattern: str = "",
        timeout: float = _PROBE_TIMEOUT_S,
    ) -> JsonObject:
        """attach on the resolved device, run one enumeration, detach.

        The device analogue of the local ``_attach_local`` + ``_run_enum`` pair:
        the whole attach/load/RPC is bounded by ``_run_deadline`` so a wedged or
        paused device process cannot park a worker, exactly as java_enumerate.
        """
        deadline = _bound_timeout(timeout)
        sessions: list[Any] = []

        def work() -> JsonObject:
            try:
                session = _invoke(device.attach, pid, timeout=deadline)
            except Exception as exc:  # noqa: BLE001
                if _is_timeout(exc):
                    raise _timeout_error(deadline) from exc
                raise FridaError("backend_error", f"attach failed: {exc}", pid=pid) from exc
            sessions.append(session)
            try:
                return self._run_enum(
                    session,
                    kind=kind,
                    module_name=module_name,
                    address=address,
                    size=size,
                    limit=limit,
                    name_filter=name_filter,
                    protection=protection,
                    scan_pattern=scan_pattern,
                )
            finally:
                with contextlib.suppress(Exception):
                    session.detach()

        try:
            return _run_deadline(
                work, timeout=deadline, on_timeout=lambda: _detach_all(sessions)
            )
        except FridaError:
            raise
        except Exception as exc:  # noqa: BLE001
            _detach_all(sessions)
            if _is_timeout(exc):
                raise _timeout_error(deadline) from exc
            raise FridaError(
                "backend_error", f"frida {kind} enumeration failed: {exc}"
            ) from exc

    def hook_template_device(
        self,
        device_id: str | None,
        pid: int,
        template: str,
        *,
        allowed_pids: Iterable[int],
        timeout: float = _PROBE_TIMEOUT_S,
    ) -> JsonObject:
        self._authorize(pid, allowed_pids)
        source = _HOOK_TEMPLATES.get(template)
        if source is None:
            raise FridaError(
                "invalid_params",
                "unknown hook template",
                template=template,
                allowed=sorted(_HOOK_TEMPLATES),
            )
        device = self._resolve_device(device_id)
        deadline = _bound_timeout(timeout)
        sessions: list[Any] = []

        def work() -> JsonObject:
            try:
                session = _invoke(device.attach, pid, timeout=deadline)
            except Exception as exc:  # noqa: BLE001
                if _is_timeout(exc):
                    raise _timeout_error(deadline) from exc
                raise FridaError("backend_error", f"attach failed: {exc}", pid=pid) from exc
            sessions.append(session)
            try:
                script = session.create_script(source)
                script.load()
                return {
                    "pid": pid,
                    "template": template,
                    "loaded": True,
                    "device": str(device_id or "local"),
                    **_PROBE_DISCLOSURE,
                }
            finally:
                with contextlib.suppress(Exception):
                    session.detach()

        try:
            return _run_deadline(
                work, timeout=deadline, on_timeout=lambda: _detach_all(sessions)
            )
        except FridaError:
            raise
        except Exception as exc:  # noqa: BLE001
            _detach_all(sessions)
            if _is_timeout(exc):
                raise _timeout_error(deadline) from exc
            raise FridaError("backend_error", f"hook template failed: {exc}") from exc

    def _authorize(self, pid: int, allowed_pids: Iterable[int]) -> None:
        if not self._available or self._frida is None:
            raise FridaError("capability_unavailable", "frida Python module is not installed")
        if type(pid) is not int or pid <= 0:
            raise FridaError("invalid_params", "pid must be a positive integer")
        allowed = set(int(value) for value in allowed_pids)
        if pid not in allowed:
            raise FridaError(
                "permission_denied",
                "pid is not in this session's authorized frida target set",
                pid=pid,
                allowed_pids=sorted(allowed),
            )
