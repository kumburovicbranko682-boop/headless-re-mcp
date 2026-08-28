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
  modules: function (limit) {
    var all = Process.enumerateModules();
    var items = [];
    var cap = Math.max(0, limit);
    for (var i = 0; i < all.length && items.length < cap; i++) {
      var m = all[i];
      items.push({name: m.name, base: m.base.toString(), size: m.size, path: m.path});
    }
    return {modules: items, total: all.length};
  },
  exports: function (moduleName, limit) {
    var mod = Process.findModuleByName(moduleName);
    if (mod === null) {
      return {found: false, exports: []};
    }
    var all = mod.enumerateExports();
    var items = [];
    for (var i = 0; i < all.length && items.length < limit; i++) {
      var e = all[i];
      items.push({name: e.name, address: e.address.toString(), type: e.type});
    }
    return {found: true, module: mod.name, base: mod.base.toString(), exports: items};
  },
  read: function (address, size) {
    // Read through the NativePointer method, not the legacy Memory.read* free
    // functions: frida 17 removed those globals, so the old form raised
    // "TypeError: not a function" and frida.memory.read failed on every modern
    // runtime. The pointer method has existed since frida 12, so this works on
    // the whole >=16.5 range the android extra pins.
    return Array.from(new Uint8Array(ptr(address).readByteArray(size)));
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
  methods: function (className, limit) {
    var out = [];
    var found = false;
    Java.perform(function () {
      var clazz;
      try {
        clazz = Java.use(className);
      } catch (e) {
        return;  // class is not loaded on the target
      }
      found = true;
      var methods = clazz.class.getDeclaredMethods();
      for (var i = 0; i < methods.length && out.length < limit; i++) {
        out.push(methods[i].toString());
      }
    });
    return {found: found, methods: out};
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


class FridaError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


# class_name, name_filter and module_name all cross the Frida RPC to the device
# as call arguments to a fixed enumeration script -- they are marshalled as data,
# never interpolated into the script -- so this bound is about resources and
# marshalling, not injection. A fully-qualified Java name with generics and inner
# classes, or a native module name/path, stays far under it; the cap keeps a
# caller from shipping a megabyte string across the RPC on every enumerate, the
# same discipline the serial, package and selector inputs already follow. A NUL
# can truncate a value mid-marshal, so it is refused outright rather than
# silently cut. Unlike package/serial there is no strict pattern: a Java name
# legitimately carries '$' (inner classes), '[' (arrays) and '.' (packages) and a
# module path carries '/', so bounding the length is the honest guard and a regex
# would reject valid targets.
_MAX_RPC_NAME_BYTES = 512


def _reject_unbounded_rpc_name(text: str, *, field: str) -> None:
    if "\x00" in text:
        raise FridaError("invalid_params", f"{field} must not contain a NUL byte", field=field)
    if len(text.encode("utf-8", "surrogatepass")) > _MAX_RPC_NAME_BYTES:
        raise FridaError(
            "invalid_params",
            f"{field} exceeds {_MAX_RPC_NAME_BYTES} bytes",
            field=field,
            limit=_MAX_RPC_NAME_BYTES,
        )


def _bounded_class_name(value: Any) -> str:
    """A required, length-bounded Java class name for frida.java.methods."""
    if not isinstance(value, str):
        raise FridaError("invalid_params", "class_name must be a string")
    name = value.strip()
    if not name:
        raise FridaError("invalid_params", "class_name is required")
    _reject_unbounded_rpc_name(name, field="class_name")
    return name


def _bounded_name_filter(value: Any) -> str:
    """An optional, length-bounded substring filter for frida.java.classes."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise FridaError("invalid_params", "name_filter must be a string")
    _reject_unbounded_rpc_name(value, field="name_filter")
    return value


def _bounded_module_name(value: Any) -> str:
    """A required, length-bounded native module name for frida.exports.

    Like class_name it is marshalled across the Frida RPC to the device (as the
    argument to the export-enumeration script), so it gets the same length / NUL
    guard rather than being shipped unbounded on every call.
    """
    if not isinstance(value, str):
        raise FridaError("invalid_params", "module_name must be a string")
    name = value.strip()
    if not name:
        raise FridaError("invalid_params", "module_name is required")
    _reject_unbounded_rpc_name(name, field="module_name")
    return name


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
        self, pid: int, *, allowed_pid: int, limit: int = 64, timeout: float = _PROBE_TIMEOUT_S
    ) -> JsonObject:
        self._require(pid, allowed_pid)
        capped = max(1, min(int(limit), 256))

        def use(script: Any) -> JsonObject:
            raw = script.exports_sync.modules(capped)
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

        return self._run_local_script(pid, _ENUM_SCRIPT, use, timeout=timeout)

    def exports(
        self,
        pid: int,
        module_name: str,
        *,
        allowed_pid: int,
        limit: int = 64,
        timeout: float = _PROBE_TIMEOUT_S,
    ) -> JsonObject:
        self._require(pid, allowed_pid)
        name = _bounded_module_name(module_name)
        capped = max(1, min(int(limit), 512))

        def use(script: Any) -> JsonObject:
            raw = script.exports_sync.exports(name, capped + 1)
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
                "module": str(raw.get("module") or name),
                "base": str(raw.get("base") or ""),
                "exports": items,
                "count": len(items),
                "has_more": has_more,
            }

        return self._run_local_script(pid, _ENUM_SCRIPT, use, timeout=timeout)

    def memory_read(
        self,
        pid: int,
        address: int,
        size: int,
        *,
        allowed_pid: int,
        timeout: float = _PROBE_TIMEOUT_S,
    ) -> JsonObject:
        self._require(pid, allowed_pid)
        if type(size) is not int or not 1 <= size <= 256 * 1024:
            raise FridaError("invalid_params", "size must be 1..262144")

        def use(script: Any) -> JsonObject:
            data = bytes(script.exports_sync.read(int(address), int(size)))
            return {
                "address": address,
                "size": size,
                "encoding": "hex",
                "data": data.hex(),
            }

        return self._run_local_script(pid, _ENUM_SCRIPT, use, timeout=timeout)

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

    def _run_local_script(
        self,
        pid: int,
        source: str,
        use: Callable[[Any], T],
        *,
        timeout: float = _PROBE_TIMEOUT_S,
    ) -> T:
        """Attach, load ``source``, hand the script to ``use``, detach -- all
        under one outer deadline.

        The read probes used to bound only the attach (via ``_attach_local``)
        and then ran ``script.load()`` and the synchronous ``exports_sync.*``
        RPC on the worker thread with no ceiling. A target that wedged while
        loading the script or enumerating (a huge module table, a faulting
        ``Memory.readByteArray``) parked that worker for good -- exactly the
        hang the device-side ops already fence off with ``_run_deadline``.
        Doing attach, load and RPC in one ``work()`` keeps them on a single
        daemon thread the caller can abandon on timeout.
        """
        deadline = _bound_timeout(timeout)
        sessions: list[Any] = []

        def work() -> T:
            try:
                session = _invoke(self._frida.attach, pid, timeout=deadline)
            except Exception as exc:  # noqa: BLE001
                if _is_timeout(exc):
                    raise _timeout_error(deadline) from exc
                raise FridaError("backend_error", f"attach failed: {exc}", pid=pid) from exc
            sessions.append(session)
            try:
                script = session.create_script(source)
                script.load()
                return use(script)
            finally:
                with contextlib.suppress(Exception):
                    session.detach()

        try:
            return _run_deadline(work, timeout=deadline, on_timeout=lambda: _detach_all(sessions))
        except FridaError:
            raise
        except Exception as exc:  # noqa: BLE001
            _detach_all(sessions)
            if _is_timeout(exc):
                raise _timeout_error(deadline) from exc
            raise FridaError("backend_error", f"frida script failed: {exc}", pid=pid) from exc

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
        # Measured: get_local_device / get_usb_device(timeout=5) /
        # get_device(..., timeout=5) / add_remote_device that slept 8s still
        # returned only after 8.000s -- frida's timeout= kwarg is not a deadline
        # this side can enforce. spawn / applications / java all resolve a
        # device before their own deadline starts, so an unattended agent held a
        # worker until the process died. Bound each lookup on a daemon thread the
        # way the enumerations already do.
        try:
            if device_id in (None, "", "local"):
                return _run_deadline(frida.get_local_device, timeout=_PROBE_TIMEOUT_S)
            if device_id == "usb":
                return _run_deadline(
                    lambda: frida.get_usb_device(timeout=5), timeout=_PROBE_TIMEOUT_S
                )
            if isinstance(device_id, str) and (":" in device_id):
                # Reuse an already-registered remote device. Re-adding it on
                # every call churns frida's device manager for what is meant to
                # be a stable connection held for the life of the session.
                mgr = frida.get_device_manager()
                with contextlib.suppress(Exception):
                    return _run_deadline(
                        lambda: mgr.get_device(device_id, timeout=1),
                        timeout=_PROBE_TIMEOUT_S,
                    )
                return _run_deadline(
                    lambda: mgr.add_remote_device(device_id), timeout=_PROBE_TIMEOUT_S
                )
            return _run_deadline(
                lambda: frida.get_device(device_id, timeout=5), timeout=_PROBE_TIMEOUT_S
            )
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
                device = _run_deadline(
                    lambda: mgr.get_device(endpoint, timeout=1), timeout=_PROBE_TIMEOUT_S
                )
            if device is None:
                # Measured: add_remote_device that slept 8s still returned only
                # after 8.000s. Bound it so a host:port that never comes back
                # cannot hold the worker until the process dies.
                device = _run_deadline(
                    lambda: mgr.add_remote_device(endpoint), timeout=_PROBE_TIMEOUT_S
                )
        except FridaError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise FridaError(
                "backend_error", f"failed to add remote device: {exc}", endpoint=endpoint
            ) from exc
        return {"id": str(device.id), "name": str(device.name), "type": str(device.type)}

    def applications(
        self, device_id: str | None, *, offset: int = 0, limit: int = 256
    ) -> JsonObject:
        device = self._resolve_device(device_id)
        try:
            apps = _run_deadline(device.enumerate_applications, timeout=30.0)
        except Exception as exc:  # noqa: BLE001
            raise FridaError("backend_error", f"failed to enumerate applications: {exc}") from exc
        items = [
            {
                "identifier": str(app.identifier),
                "name": str(app.name),
                "pid": int(getattr(app, "pid", 0) or 0),
            }
            for app in apps
        ]
        # Sort before paging, then page by offset -- like apk.classes/xrefs.
        # enumerate_applications hands back device order, and the reader used to
        # cap at the first page with no offset, so a device with more apps than
        # the cap returned an unsorted first slice and left the rest unreachable:
        # an agent could not find (or even page to) a package that sorted or sat
        # past the cap. Sort by identifier (the package id a caller keys on), then
        # name for a stable tiebreak, so the page is a real alphabetical prefix
        # and a larger offset walks the remaining apps.
        items.sort(key=lambda entry: (entry["identifier"], entry["name"]))
        start = max(0, int(offset))
        cap = max(1, min(int(limit), 1000))
        window = items[start : start + cap]
        return {
            "applications": window,
            "count": len(window),
            "total": len(items),
            "offset": start,
            "has_more": start + len(window) < len(items),
        }

    def spawn(
        self,
        device_id: str | None,
        package: str,
        *,
        timeout: float = _PROBE_TIMEOUT_S,
    ) -> JsonObject:
        # Validate the package before resolving the device, matching
        # java_enumerate's class_name / name_filter ordering: a malformed local
        # argument should fail fast and precisely (invalid_params) rather than
        # after the cost of resolving a device, or hidden behind the
        # capability_unavailable that _resolve_device raises when frida is
        # missing -- a bad package id is a bad package id with or without a device.
        if not isinstance(package, str) or not package.strip():
            raise FridaError("invalid_params", "package is required")
        pkg = package.strip()
        if not _ANDROID_PACKAGE_RE.match(pkg):
            raise FridaError(
                "invalid_params",
                "package must be an Android package id",
                package=pkg,
            )
        device = self._resolve_device(device_id)
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
        timeout: float = _PROBE_TIMEOUT_S,
    ) -> JsonObject:
        self._authorize(pid, allowed_pids)
        # Validate the mode and bound the caller's strings before resolving the
        # device: these are cheap local facts, so a bad mode or an over-long
        # class_name / name_filter fails fast rather than after an attach --
        # the same "check what is local first" ordering install and push use.
        if mode not in ("classes", "methods"):
            raise FridaError("invalid_params", "mode must be classes or methods", mode=mode)
        filter_text = _bounded_name_filter(name_filter) if mode == "classes" else ""
        class_target = _bounded_class_name(class_name) if mode == "methods" else ""
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
                        script.exports_sync.classes(filter_text, capped + 1), capped
                    )
                    return {"classes": values, "count": len(values), "has_more": has_more}
                raw = script.exports_sync.methods(class_target, capped + 1)
                # found distinguishes "class is not loaded on the target"
                # (found false, methods empty) from "loaded, but declares no
                # methods of its own" (found true, methods empty) -- an empty
                # list alone read as the latter and hid a bad class name. The
                # bare-array branch tolerates the older script shape, exactly
                # as ``modules`` does.
                if isinstance(raw, dict):
                    found = bool(raw.get("found"))
                    values, has_more = _page(list(raw.get("methods") or []), capped)
                else:
                    found = True
                    values, has_more = _page(list(raw or []), capped)
                return {
                    "class_name": class_target,
                    "found": found,
                    "methods": values,
                    "count": len(values),
                    "has_more": has_more,
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
            raise FridaError("backend_error", f"java enumeration failed: {exc}") from exc

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
