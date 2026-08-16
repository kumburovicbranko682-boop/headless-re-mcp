from __future__ import annotations

import contextlib
import threading
from collections.abc import Iterable
from typing import Any

JsonObject = dict[str, Any]
_ATTACH_TIMEOUT = 15.0
_SPAWN_TIMEOUT = 15.0
_RESUME_TIMEOUT = 15.0
_APPLICATIONS_TIMEOUT = 15.0
_DEVICES_TIMEOUT = 15.0
_REMOTE_TIMEOUT = 15.0
_LOCAL_DEVICE_TIMEOUT = 15.0

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
  modules: function () {
    return Process.enumerateModules().map(function (m) {
      return {name: m.name, base: m.base.toString(), size: m.size, path: m.path};
    });
  },
  exports: function (moduleName, limit) {
    var mod = Process.findModuleByName(moduleName);
    if (mod === null) {
      return {found: false, exports: []};
    }
    var items = mod.enumerateExports().slice(0, limit).map(function (e) {
      return {name: e.name, address: e.address.toString(), type: e.type};
    });
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
      Java.enumerateLoadedClassesSync().forEach(function (name) {
        if (out.length < limit && (!filter || name.indexOf(filter) !== -1)) {
          out.push(name);
        }
      });
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
    def attach(self, pid: int, *, allowed_pid: int) -> JsonObject:
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
        session = self._attach_with_deadline(pid)
        try:
            return {
                "pid": pid,
                "attached": True,
                "device": "local",
                "note": "probe attach; detached immediately",
            }
        finally:
            session.detach()

    def _attach_with_deadline(self, pid: int, *, attach: Any | None = None) -> Any:
        """Attach with a deadline. ``frida.attach`` has none.

        Measured: a 0.8s sleep in attach held ``frida.attach`` 0.8s. A
        wedged target pins the worker; get_usb_device already has a
        timeout, this hop did not.
        """
        target = attach if attach is not None else self._frida.attach
        box: list[Any] = []
        err: list[BaseException] = []

        def run() -> None:
            try:
                box.append(target(pid))
            except BaseException as exc:  # noqa: BLE001
                err.append(exc)

        thread = threading.Thread(target=run, name=f"frida-attach-{pid}", daemon=True)
        thread.start()
        thread.join(_ATTACH_TIMEOUT)
        if thread.is_alive():
            raise FridaError(
                "timeout",
                f"frida attach timed out after {_ATTACH_TIMEOUT:g}s",
                pid=pid,
            )
        if err:
            raise err[0]
        if not box:
            raise FridaError("backend_error", "frida attach returned nothing", pid=pid)
        return box[0]

    def _spawn_with_deadline(self, device: Any, package: str) -> int:
        """Spawn with a deadline. ``device.spawn`` has none.

        Measured: a 0.8s sleep in spawn held ``frida.spawn`` 0.8s. A
        wedged device pins the worker; get_usb_device already has a
        timeout, this hop did not.
        """
        box: list[Any] = []
        err: list[BaseException] = []

        def run() -> None:
            try:
                box.append(device.spawn([package]))
            except BaseException as exc:  # noqa: BLE001
                err.append(exc)

        thread = threading.Thread(target=run, name=f"frida-spawn-{package}", daemon=True)
        thread.start()
        thread.join(_SPAWN_TIMEOUT)
        if thread.is_alive():
            raise FridaError(
                "timeout",
                f"frida spawn timed out after {_SPAWN_TIMEOUT:g}s",
                package=package,
            )
        if err:
            raise err[0]
        if not box:
            raise FridaError("backend_error", "frida spawn returned nothing", package=package)
        return int(box[0])

    def _resume_with_deadline(self, device: Any, pid: int) -> None:
        """Resume with a deadline. ``device.resume`` has none.

        Measured: a 0.8s sleep in resume held ``frida.spawn`` 0.8s after
        spawn itself already returned. A wedged resume pins the worker
        with a frozen target.
        """
        err: list[BaseException] = []

        def run() -> None:
            try:
                device.resume(pid)
            except BaseException as exc:  # noqa: BLE001
                err.append(exc)

        thread = threading.Thread(target=run, name=f"frida-resume-{pid}", daemon=True)
        thread.start()
        thread.join(_RESUME_TIMEOUT)
        if thread.is_alive():
            raise FridaError(
                "timeout",
                f"frida resume timed out after {_RESUME_TIMEOUT:g}s",
                pid=pid,
            )
        if err:
            raise err[0]

    def _applications_with_deadline(self, device: Any) -> Any:
        """List apps with a deadline. ``enumerate_applications`` has none.

        Measured: a 0.8s sleep in that hop held ``frida.applications``
        0.8s. A wedged device pins the worker.
        """
        box: list[Any] = []
        err: list[BaseException] = []

        def run() -> None:
            try:
                box.append(device.enumerate_applications())
            except BaseException as exc:  # noqa: BLE001
                err.append(exc)

        thread = threading.Thread(target=run, name="frida-applications", daemon=True)
        thread.start()
        thread.join(_APPLICATIONS_TIMEOUT)
        if thread.is_alive():
            raise FridaError(
                "timeout",
                f"frida applications timed out after {_APPLICATIONS_TIMEOUT:g}s",
            )
        if err:
            raise err[0]
        if not box:
            raise FridaError("backend_error", "frida applications returned nothing")
        return box[0]

    def _devices_with_deadline(self, frida: Any) -> Any:
        """List devices with a deadline. ``enumerate_devices`` has none.

        Measured: a 0.8s sleep in that hop held ``enumerate_devices``
        0.8s. A wedged Frida server pins the worker.
        """
        box: list[Any] = []
        err: list[BaseException] = []

        def run() -> None:
            try:
                box.append(frida.enumerate_devices())
            except BaseException as exc:  # noqa: BLE001
                err.append(exc)

        thread = threading.Thread(target=run, name="frida-devices", daemon=True)
        thread.start()
        thread.join(_DEVICES_TIMEOUT)
        if thread.is_alive():
            raise FridaError(
                "timeout",
                f"frida devices timed out after {_DEVICES_TIMEOUT:g}s",
            )
        if err:
            raise err[0]
        if not box:
            raise FridaError("backend_error", "frida devices returned nothing")
        return box[0]

    def _remote_with_deadline(self, frida: Any, endpoint: str) -> Any:
        """Add a remote device with a deadline. ``add_remote_device`` has none.

        Measured: a 0.8s sleep in that hop held the call 0.8s. A
        unreachable endpoint pins the worker.
        """
        box: list[Any] = []
        err: list[BaseException] = []

        def run() -> None:
            try:
                box.append(frida.get_device_manager().add_remote_device(endpoint))
            except BaseException as exc:  # noqa: BLE001
                err.append(exc)

        thread = threading.Thread(target=run, name="frida-remote", daemon=True)
        thread.start()
        thread.join(_REMOTE_TIMEOUT)
        if thread.is_alive():
            raise FridaError(
                "timeout",
                f"frida remote device timed out after {_REMOTE_TIMEOUT:g}s",
                endpoint=endpoint,
            )
        if err:
            raise err[0]
        if not box:
            raise FridaError(
                "backend_error",
                "frida remote device returned nothing",
                endpoint=endpoint,
            )
        return box[0]

    def _local_device_with_deadline(self, frida: Any) -> Any:
        """Resolve the local device with a deadline. ``get_local_device`` has none.

        Measured: a 0.8s sleep in that hop held ``applications("local")``
        0.8s. A wedged local backend pins the worker.
        """
        box: list[Any] = []
        err: list[BaseException] = []

        def run() -> None:
            try:
                box.append(frida.get_local_device())
            except BaseException as exc:  # noqa: BLE001
                err.append(exc)

        thread = threading.Thread(target=run, name="frida-local-device", daemon=True)
        thread.start()
        thread.join(_LOCAL_DEVICE_TIMEOUT)
        if thread.is_alive():
            raise FridaError(
                "timeout",
                f"frida local device timed out after {_LOCAL_DEVICE_TIMEOUT:g}s",
            )
        if err:
            raise err[0]
        if not box:
            raise FridaError("backend_error", "frida local device returned nothing")
        return box[0]

    def modules(self, pid: int, *, allowed_pid: int, limit: int = 64) -> JsonObject:
        self._require(pid, allowed_pid)
        session = self._attach_with_deadline(pid)
        try:
            script = session.create_script(_ENUM_SCRIPT)
            script.load()
            mods = list(script.exports_sync.modules())
            capped = max(1, min(int(limit), 256))
            items = [
                {
                    "name": str(item.get("name", "")),
                    "base": str(item.get("base", "")),
                    "size": int(item.get("size", 0) or 0),
                    "path": str(item.get("path", "")),
                }
                for item in mods[:capped]
            ]
            return {
                "modules": items,
                "count": len(items),
                "total": len(mods),
                "has_more": len(mods) > len(items),
            }
        finally:
            session.detach()

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
        session = self._attach_with_deadline(pid)
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
            return {
                "found": bool(raw.get("found")),
                "module": str(raw.get("module") or module_name),
                "base": str(raw.get("base") or ""),
                "exports": items,
                "count": len(items),
                "has_more": has_more,
            }
        finally:
            session.detach()

    def memory_read(
        self, pid: int, address: int, size: int, *, allowed_pid: int
    ) -> JsonObject:
        self._require(pid, allowed_pid)
        if type(size) is not int or not 1 <= size <= 256 * 1024:
            raise FridaError("invalid_params", "size must be 1..262144")
        session = self._attach_with_deadline(pid)
        try:
            script = session.create_script(_ENUM_SCRIPT)
            script.load()
            data = bytes(script.exports_sync.read(int(address), int(size)))
            return {
                "address": address,
                "size": size,
                "encoding": "hex",
                "data": data.hex(),
            }
        finally:
            session.detach()

    def hook_template(self, pid: int, template: str, *, allowed_pid: int) -> JsonObject:
        self._require(pid, allowed_pid)
        source = _HOOK_TEMPLATES.get(template)
        if source is None:
            raise FridaError(
                "invalid_params",
                "unknown hook template",
                template=template,
                allowed=sorted(_HOOK_TEMPLATES),
            )
        session = self._attach_with_deadline(pid)
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
            session.detach()

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
                return self._local_device_with_deadline(frida)
            if device_id == "usb":
                return frida.get_usb_device(timeout=5)
            if isinstance(device_id, str) and (":" in device_id):
                # Reuse an already-registered remote device. Re-adding it on
                # every call churns frida's device manager for what is meant to
                # be a stable connection held for the life of the session.
                mgr = frida.get_device_manager()
                with contextlib.suppress(Exception):
                    return mgr.get_device(device_id, timeout=1)
                return self._remote_with_deadline(frida, device_id)
            return frida.get_device(device_id, timeout=5)
        except FridaError:
            raise
        except Exception as exc:  # noqa: BLE001 - frida raises many device errors
            raise FridaError(
                "not_found", f"frida device unavailable: {exc}", device_id=device_id
            ) from exc

    def enumerate_devices(self, *, limit: int = 32) -> JsonObject:
        """List Frida devices. The reply is capped.

        Measured: five devices, count=5, no total or has_more. A page
        looked like every device Frida could see.
        """
        frida = self._need()
        try:
            devices = self._devices_with_deadline(frida)
        except FridaError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise FridaError("backend_error", f"failed to enumerate devices: {exc}") from exc
        capped = max(1, min(int(limit), 256))
        items = [
            {"id": str(dev.id), "name": str(dev.name), "type": str(dev.type)}
            for dev in devices[:capped]
        ]
        return {
            "devices": items,
            "count": len(items),
            "total": len(devices),
            "has_more": len(devices) > len(items),
        }

    def add_remote_device(self, endpoint: str) -> JsonObject:
        frida = self._need()
        try:
            device = self._remote_with_deadline(frida, endpoint)
        except FridaError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise FridaError(
                "backend_error", f"failed to add remote device: {exc}", endpoint=endpoint
            ) from exc
        return {"id": str(device.id), "name": str(device.name), "type": str(device.type)}

    def applications(self, device_id: str | None, *, limit: int = 256) -> JsonObject:
        device = self._resolve_device(device_id)
        try:
            apps = self._applications_with_deadline(device)
        except FridaError:
            raise
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
            "has_more": len(apps) > len(items),
        }

    def spawn(self, device_id: str | None, package: str) -> JsonObject:
        device = self._resolve_device(device_id)
        if not isinstance(package, str) or not package.strip():
            raise FridaError("invalid_params", "package is required")
        try:
            pid = self._spawn_with_deadline(device, package.strip())
            self._resume_with_deadline(device, int(pid))
        except FridaError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise FridaError("backend_error", f"spawn failed: {exc}", package=package) from exc
        return {"package": package.strip(), "pid": int(pid), "device": str(device_id or "local")}

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
    ) -> JsonObject:
        self._authorize(pid, allowed_pids)
        device = self._resolve_device(device_id)
        capped = max(1, min(int(limit), 2000))
        try:
            session = self._attach_with_deadline(pid, attach=device.attach)
        except FridaError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise FridaError("backend_error", f"attach failed: {exc}", pid=pid) from exc
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
                values, has_more = _page(
                    script.exports_sync.methods(class_name, capped + 1), capped
                )
                return {
                    "class_name": class_name,
                    "methods": values,
                    "count": len(values),
                    "has_more": has_more,
                }
            raise FridaError("invalid_params", "mode must be classes or methods")
        except FridaError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise FridaError("backend_error", f"java enumeration failed: {exc}") from exc
        finally:
            session.detach()

    def hook_template_device(
        self,
        device_id: str | None,
        pid: int,
        template: str,
        *,
        allowed_pids: Iterable[int],
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
        try:
            session = self._attach_with_deadline(pid, attach=device.attach)
        except FridaError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise FridaError("backend_error", f"attach failed: {exc}", pid=pid) from exc
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
            session.detach()

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
