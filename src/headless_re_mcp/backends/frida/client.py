from __future__ import annotations

import contextlib
import re
from collections.abc import Callable, Iterable
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeout
from inspect import signature
from threading import BoundedSemaphore, Event, Thread
from typing import Any, TypeVar

from headless_re_mcp.core.limits import MAX_WORKFLOW_TIMEOUT

JsonObject = dict[str, Any]
T = TypeVar("T")
_MAX_DEADLINE_THREADS = 8
_DEADLINE_SLOTS = BoundedSemaphore(_MAX_DEADLINE_THREADS)
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
  methods: function (className, limit) {
    var out = [];
    Java.perform(function () {
      var clazz = Java.use(className);
      var methods = clazz.class.getDeclaredMethods();
      for (var i = 0; i < methods.length && out.length < limit; i++) {
        out.push(methods[i].toString());
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


def _detach_all(sessions: list[Any]) -> list[JsonObject]:
    failures: list[JsonObject] = []
    while sessions:
        session = sessions.pop()
        try:
            session.detach()
        except Exception as exc:
            failures.append(
                {
                    "detach_error": f"{type(exc).__name__}: {exc}",
                }
            )
    return failures


def _kill_spawned(device: Any, pids: list[int]) -> list[JsonObject]:
    failures: list[JsonObject] = []
    while pids:
        pid = pids.pop()
        try:
            device.kill(pid)
        except Exception as exc:
            failures.append(
                {
                    "pid": pid,
                    "kill_error": f"{type(exc).__name__}: {exc}",
                }
            )
    return failures


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
    slots = _DEADLINE_SLOTS
    if not slots.acquire(blocking=False):
        # A timed-out native call cannot be killed safely, but allowing another
        # one to start turns each timeout into one more permanent daemon thread.
        raise FridaError(
            "resource_exhausted",
            f"all {_MAX_DEADLINE_THREADS} Frida deadline workers are still occupied",
        )
    done: Future[T] = Future()

    def run() -> None:
        try:
            done.set_result(work())
        except BaseException as exc:  # noqa: BLE001 - handed to the caller
            if not done.done():
                done.set_exception(exc)
        finally:
            slots.release()

    thread = Thread(target=run, name="frida-deadline", daemon=True)
    try:
        thread.start()
    except BaseException:
        slots.release()
        raise
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
            session.detach()
        except Exception as exc:
            raise FridaError(
                "frida_detach_failed",
                f"probe detach failed: {type(exc).__name__}: {exc}",
                pid=pid,
            ) from exc
        return {
            "pid": pid,
            "attached": True,
            "device": "local",
            "note": "probe attach; detached immediately",
        }

    def modules(self, pid: int, *, allowed_pid: int, limit: int = 64) -> JsonObject:
        self._require(pid, allowed_pid)
        session = self._attach_local(pid)
        try:
            script = session.create_script(_ENUM_SCRIPT)
            script.load()
            capped = max(1, min(int(limit), 256))
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
            result = {
                "modules": items,
                "count": len(items),
                "total": total,
                "has_more": total > len(items),
            }
        except BaseException:
            with contextlib.suppress(Exception):
                session.detach()
            raise
        try:
            session.detach()
        except Exception as exc:
            raise FridaError(
                "frida_detach_failed",
                f"module probe detach failed: {type(exc).__name__}: {exc}",
                pid=pid,
            ) from exc
        return result

    def exports(
        self,
        pid: int,
        module_name: str,
        *,
        allowed_pid: int,
        limit: int = 64,
    ) -> JsonObject:
        self._require(pid, allowed_pid)
        if not isinstance(module_name, str) or not module_name.strip():
            raise FridaError("invalid_params", "module_name is required")
        capped = max(1, min(int(limit), 512))
        session = self._attach_local(pid)
        try:
            script = session.create_script(_ENUM_SCRIPT)
            script.load()
            raw = script.exports_sync.exports(module_name.strip(), capped + 1)
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
            result = {
                "found": bool(raw.get("found")),
                "module": str(raw.get("module") or module_name),
                "base": str(raw.get("base") or ""),
                "exports": items,
                "count": len(items),
                "has_more": has_more,
            }
        except BaseException:
            with contextlib.suppress(Exception):
                session.detach()
            raise
        try:
            session.detach()
        except Exception as exc:
            raise FridaError(
                "frida_detach_failed",
                f"export probe detach failed: {type(exc).__name__}: {exc}",
                pid=pid,
            ) from exc
        return result

    def memory_read(
        self, pid: int, address: int, size: int, *, allowed_pid: int
    ) -> JsonObject:
        self._require(pid, allowed_pid)
        if type(size) is not int or not 1 <= size <= 256 * 1024:
            raise FridaError("invalid_params", "size must be 1..262144")
        session = self._attach_local(pid)
        try:
            script = session.create_script(_ENUM_SCRIPT)
            script.load()
            data = bytes(script.exports_sync.read(int(address), int(size)))
            result = {
                "address": address,
                "size": size,
                "encoding": "hex",
                "data": data.hex(),
            }
        except BaseException:
            with contextlib.suppress(Exception):
                session.detach()
            raise
        try:
            session.detach()
        except Exception as exc:
            raise FridaError(
                "frida_detach_failed",
                f"memory probe detach failed: {type(exc).__name__}: {exc}",
                pid=pid,
            ) from exc
        return result

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
        cleanup_failures: list[JsonObject] = []

        def cleanup_sessions() -> None:
            cleanup_failures.extend(_detach_all(sessions))

        def cleanup_error() -> FridaError:
            first = cleanup_failures[0]
            return FridaError(
                "frida_detach_failed",
                f"{len(cleanup_failures)} local hook detach attempt(s) failed",
                pid=pid,
                detach_error=first["detach_error"],
                failed_count=len(cleanup_failures),
                failures=cleanup_failures,
            )

        def work() -> JsonObject:
            session = _invoke(self._frida.attach, pid, timeout=deadline)
            sessions.append(session)
            try:
                script = session.create_script(source)
                script.load()
            except BaseException:
                with contextlib.suppress(Exception):
                    session.detach()
                raise
            try:
                session.detach()
            except Exception as exc:
                raise FridaError(
                    "frida_detach_failed",
                    f"hook probe detach failed: {type(exc).__name__}: {exc}",
                    pid=pid,
                ) from exc
            return {
                "pid": pid,
                "template": template,
                "loaded": True,
                "device": "local",
                **_PROBE_DISCLOSURE,
            }

        try:
            return _run_deadline(work, timeout=deadline, on_timeout=cleanup_sessions)
        except FridaError as exc:
            if cleanup_failures:
                raise cleanup_error() from exc
            raise
        except Exception as exc:  # noqa: BLE001
            if _is_timeout(exc):
                cleanup_sessions()
                if cleanup_failures:
                    raise cleanup_error() from exc
                raise _timeout_error(deadline) from exc
            raise

    def _attach_local(self, pid: int, *, timeout: float = _PROBE_TIMEOUT_S) -> Any:
        deadline = _bound_timeout(timeout)
        sessions: list[Any] = []
        expired = Event()

        def cleanup_sessions() -> None:
            expired.set()
            _detach_all(sessions)

        def work() -> Any:
            session = _invoke(self._frida.attach, pid, timeout=deadline)
            sessions.append(session)
            # The deadline callback may have run before attach returned, when
            # there was no session to detach. Close that race in the worker.
            if expired.is_set():
                _detach_all(sessions)
            return session

        try:
            return _run_deadline(
                work, timeout=deadline, on_timeout=cleanup_sessions
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

    def applications(self, device_id: str | None, *, limit: int = 256) -> JsonObject:
        device = self._resolve_device(device_id)
        try:
            apps = _run_deadline(device.enumerate_applications, timeout=30.0)
        except Exception as exc:  # noqa: BLE001
            raise FridaError("backend_error", f"failed to enumerate applications: {exc}") from exc
        capped = max(1, min(int(limit), 1000))
        items = [
            {
                "identifier": str(app.identifier),
                "name": str(app.name),
                "pid": int(getattr(app, "pid", 0) or 0),
            }
            for app in apps[:capped]
        ]
        return {
            "applications": items,
            "count": len(items),
            "total": len(apps),
            "has_more": len(apps) > capped,
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
        cleanup_failures: list[JsonObject] = []

        def cleanup_spawned() -> None:
            cleanup_failures.extend(_kill_spawned(device, pids))

        def cleanup_error() -> FridaError:
            first = cleanup_failures[0]
            return FridaError(
                "frida_spawn_cleanup_failed",
                f"{len(cleanup_failures)} spawned process cleanup attempt(s) failed",
                package=pkg,
                pid=first["pid"],
                kill_error=first["kill_error"],
                failed_count=len(cleanup_failures),
                failures=cleanup_failures,
            )

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
            except Exception as exc:  # noqa: BLE001
                try:
                    device.kill(spawned)
                except Exception as kill_exc:
                    raise FridaError(
                        "frida_spawn_cleanup_failed",
                        f"spawned pid {spawned} could not be killed after resume failed",
                        package=pkg,
                        pid=spawned,
                        resume_error=f"{type(exc).__name__}: {exc}",
                        kill_error=f"{type(kill_exc).__name__}: {kill_exc}",
                    ) from kill_exc
                if isinstance(exc, FridaError):
                    raise
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
                work, timeout=deadline, on_timeout=cleanup_spawned
            )
        except FridaError as exc:
            if cleanup_failures:
                raise cleanup_error() from exc
            raise
        except Exception as exc:  # noqa: BLE001
            cleanup_spawned()
            if cleanup_failures:
                raise cleanup_error() from exc
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
        device = self._resolve_device(device_id)
        capped = max(1, min(int(limit), 2000))
        deadline = _bound_timeout(timeout)
        sessions: list[Any] = []
        cleanup_failures: list[JsonObject] = []

        def cleanup_sessions() -> None:
            cleanup_failures.extend(_detach_all(sessions))

        def cleanup_error() -> FridaError:
            first = cleanup_failures[0]
            return FridaError(
                "frida_detach_failed",
                f"{len(cleanup_failures)} Java probe detach attempt(s) failed",
                pid=pid,
                detach_error=first["detach_error"],
                failed_count=len(cleanup_failures),
                failures=cleanup_failures,
            )

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
                    result: JsonObject = {
                        "classes": values,
                        "count": len(values),
                        "has_more": has_more,
                    }
                elif mode == "methods":
                    if not class_name:
                        raise FridaError("invalid_params", "class_name is required")
                    values, has_more = _page(
                        script.exports_sync.methods(class_name, capped + 1), capped
                    )
                    result = {
                        "class_name": class_name,
                        "methods": values,
                        "count": len(values),
                        "has_more": has_more,
                    }
                else:
                    raise FridaError("invalid_params", "mode must be classes or methods")
            except BaseException:
                with contextlib.suppress(Exception):
                    session.detach()
                raise
            try:
                session.detach()
            except Exception as exc:
                raise FridaError(
                    "frida_detach_failed",
                    f"Java probe detach failed: {type(exc).__name__}: {exc}",
                    pid=pid,
                ) from exc
            return result

        try:
            return _run_deadline(
                work, timeout=deadline, on_timeout=cleanup_sessions
            )
        except FridaError as exc:
            if cleanup_failures:
                raise cleanup_error() from exc
            raise
        except Exception as exc:  # noqa: BLE001
            cleanup_sessions()
            if cleanup_failures:
                raise cleanup_error() from exc
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
        cleanup_failures: list[JsonObject] = []

        def cleanup_sessions() -> None:
            cleanup_failures.extend(_detach_all(sessions))

        def cleanup_error() -> FridaError:
            first = cleanup_failures[0]
            return FridaError(
                "frida_detach_failed",
                f"{len(cleanup_failures)} device hook detach attempt(s) failed",
                pid=pid,
                detach_error=first["detach_error"],
                failed_count=len(cleanup_failures),
                failures=cleanup_failures,
            )

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
            except BaseException:
                with contextlib.suppress(Exception):
                    session.detach()
                raise
            try:
                session.detach()
            except Exception as exc:
                raise FridaError(
                    "frida_detach_failed",
                    f"device hook probe detach failed: {type(exc).__name__}: {exc}",
                    pid=pid,
                ) from exc
            return {
                "pid": pid,
                "template": template,
                "loaded": True,
                "device": str(device_id or "local"),
                **_PROBE_DISCLOSURE,
            }

        try:
            return _run_deadline(
                work, timeout=deadline, on_timeout=cleanup_sessions
            )
        except FridaError as exc:
            if cleanup_failures:
                raise cleanup_error() from exc
            raise
        except Exception as exc:  # noqa: BLE001
            cleanup_sessions()
            if cleanup_failures:
                raise cleanup_error() from exc
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
